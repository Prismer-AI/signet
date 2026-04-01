import pytest
from signet_auth import SigningAgent, KeyNotFoundError, Receipt


def test_create_agent(tmp_path):
    agent = SigningAgent.create("test-agent", owner="me", signet_dir=str(tmp_path))
    assert agent.name == "test-agent"
    assert agent.owner == "me"
    assert isinstance(agent.public_key, str)
    assert agent.signet_dir == str(tmp_path)


def test_create_agent_no_owner(tmp_path):
    agent = SigningAgent.create("no-owner", signet_dir=str(tmp_path))
    assert agent.owner is None


def test_load_agent(tmp_path):
    SigningAgent.create("load-me", owner="x", signet_dir=str(tmp_path))
    agent = SigningAgent("load-me", signet_dir=str(tmp_path))
    assert agent.name == "load-me"
    assert agent.owner == "x"


def test_load_agent_not_found(tmp_path):
    with pytest.raises(KeyNotFoundError):
        SigningAgent("nonexistent", signet_dir=str(tmp_path))


def test_load_agent_with_passphrase(tmp_path):
    SigningAgent.create("enc", passphrase="secret", signet_dir=str(tmp_path))
    agent = SigningAgent("enc", passphrase="secret", signet_dir=str(tmp_path))
    assert agent.name == "enc"


def test_sign_basic(tmp_path):
    agent = SigningAgent.create("signer", signet_dir=str(tmp_path))
    receipt = agent.sign("test_tool", params={"k": "v"})
    assert isinstance(receipt, Receipt)
    assert receipt.action.tool == "test_tool"
    assert receipt.signer.name == "signer"


def test_sign_with_audit(tmp_path):
    agent = SigningAgent.create("audited", signet_dir=str(tmp_path))
    agent.sign("tool1", audit=True)
    agent.sign("tool2", audit=True)
    records = agent.audit_query()
    assert len(records) == 2


def test_sign_without_audit(tmp_path):
    agent = SigningAgent.create("no-audit", signet_dir=str(tmp_path))
    agent.sign("tool1", audit=False)
    records = agent.audit_query()
    assert len(records) == 0


def test_sign_audit_failure_raises(tmp_path):
    agent = SigningAgent.create("bad-audit", signet_dir=str(tmp_path))
    audit_dir = tmp_path / "audit"
    audit_dir.write_text("not a directory")
    with pytest.raises(Exception):
        agent.sign("tool1", audit=True)


def test_verify_own_receipt(tmp_path):
    agent = SigningAgent.create("verifier", signet_dir=str(tmp_path))
    receipt = agent.sign("tool", audit=False)
    assert agent.verify(receipt) is True


def test_verify_with_key_static(tmp_path):
    agent = SigningAgent.create("static-v", signet_dir=str(tmp_path))
    receipt = agent.sign("tool", audit=False)
    assert SigningAgent.verify_with_key(receipt, agent.public_key) is True


def test_audit_query_auto_filters_signer(tmp_path):
    a1 = SigningAgent.create("agent-a", signet_dir=str(tmp_path))
    a2 = SigningAgent.create("agent-b", signet_dir=str(tmp_path))
    a1.sign("tool")
    a2.sign("tool")
    assert len(a1.audit_query()) == 1
    assert len(a2.audit_query()) == 1


def test_audit_verify_chain(tmp_path):
    agent = SigningAgent.create("chain", signet_dir=str(tmp_path))
    agent.sign("tool1")
    agent.sign("tool2")
    status = agent.audit_verify_chain()
    assert status.valid is True
    assert status.total_records == 2


def test_audit_verify_signatures(tmp_path):
    agent = SigningAgent.create("sig-check", signet_dir=str(tmp_path))
    agent.sign("tool1")
    result = agent.audit_verify_signatures()
    assert result.total == 1
    assert result.valid == 1


def test_key_info_property(tmp_path):
    agent = SigningAgent.create("info-test", owner="Owner", signet_dir=str(tmp_path))
    info = agent.key_info
    assert info.name == "info-test"
    assert info.owner == "Owner"
