import pytest
from signet_auth import SigningAgent, BilateralReceipt, KeyNotFoundError, Receipt, SignetIOError


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


def test_sign_with_encrypted_audit(tmp_path):
    agent = SigningAgent.create("enc-audited", signet_dir=str(tmp_path))
    agent.sign("tool1", params={"secret": "value"}, audit_encrypt_params=True)
    records = agent.audit_query()
    assert "params" not in records[0].receipt["action"]
    decrypted = agent.audit_query(decrypt_params=True)
    assert decrypted[0].receipt["action"]["params"]["secret"] == "value"


def test_sign_without_audit(tmp_path):
    agent = SigningAgent.create("no-audit", signet_dir=str(tmp_path))
    agent.sign("tool1", audit=False)
    records = agent.audit_query()
    assert len(records) == 0


def test_sign_rejects_encrypted_audit_without_audit(tmp_path):
    agent = SigningAgent.create("enc-no-audit", signet_dir=str(tmp_path))
    with pytest.raises(ValueError, match="audit_encrypt_params requires audit=True"):
        agent.sign("tool1", audit=False, audit_encrypt_params=True)


def test_sign_audit_failure_raises(tmp_path):
    agent = SigningAgent.create("bad-audit", signet_dir=str(tmp_path))
    audit_dir = tmp_path / "audit"
    audit_dir.write_text("not a directory")
    with pytest.raises(SignetIOError):
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


def test_audit_query_decrypt_params_with_passphrase(tmp_path):
    agent = SigningAgent.create("enc-pass", passphrase="secret", signet_dir=str(tmp_path))
    agent.sign("tool1", params={"secret": "value"}, audit_encrypt_params=True)
    records = agent.audit_query(decrypt_params=True)
    assert records[0].receipt["action"]["params"]["secret"] == "value"


def test_key_info_property(tmp_path):
    agent = SigningAgent.create("info-test", owner="Owner", signet_dir=str(tmp_path))
    info = agent.key_info
    assert info.name == "info-test"
    assert info.owner == "Owner"


def test_agent_close(tmp_path):
    agent = SigningAgent.create("closable", signet_dir=str(tmp_path))
    agent.sign("tool", audit=False)
    agent.close()
    with pytest.raises(RuntimeError, match="closed"):
        agent.sign("tool", audit=False)


def test_agent_context_manager(tmp_path):
    with SigningAgent.create("ctx", signet_dir=str(tmp_path)) as agent:
        receipt = agent.sign("tool", audit=False)
        assert receipt.action.tool == "tool"
    with pytest.raises(RuntimeError, match="closed"):
        agent.sign("tool", audit=False)


def test_sign_bilateral_roundtrip(tmp_path):
    client = SigningAgent.create("client-agent", signet_dir=str(tmp_path))
    server = SigningAgent.create("server-agent", signet_dir=str(tmp_path))

    agent_receipt = client.sign("web_search", params={"query": "signet"}, audit=False)
    bilateral = server.sign_bilateral(agent_receipt, response_content={"results": ["a", "b"]})

    assert isinstance(bilateral, BilateralReceipt)
    assert bilateral.v == 3
    assert bilateral.server.name == "server-agent"
    assert bilateral.agent_receipt.action.tool == "web_search"


def test_verify_bilateral_receipt(tmp_path):
    client = SigningAgent.create("c", signet_dir=str(tmp_path))
    server = SigningAgent.create("s", signet_dir=str(tmp_path))

    agent_receipt = client.sign("tool", audit=False)
    bilateral = server.sign_bilateral(agent_receipt, response_content={"ok": True})

    assert server.verify_bilateral_receipt(bilateral) is True


def test_verify_bilateral_wrong_key(tmp_path):
    client = SigningAgent.create("c2", signet_dir=str(tmp_path))
    server = SigningAgent.create("s2", signet_dir=str(tmp_path))
    other = SigningAgent.create("other", signet_dir=str(tmp_path))

    agent_receipt = client.sign("tool", audit=False)
    bilateral = server.sign_bilateral(agent_receipt)

    assert other.verify_bilateral_receipt(bilateral) is False


def test_verify_bilateral_with_key_static(tmp_path):
    client = SigningAgent.create("c3", signet_dir=str(tmp_path))
    server = SigningAgent.create("s3", signet_dir=str(tmp_path))

    agent_receipt = client.sign("tool", audit=False)
    bilateral = server.sign_bilateral(agent_receipt, response_content={})

    assert SigningAgent.verify_bilateral_with_key(bilateral, server.public_key) is True


def test_sign_bilateral_after_close(tmp_path):
    client = SigningAgent.create("c4", signet_dir=str(tmp_path))
    server = SigningAgent.create("s4", signet_dir=str(tmp_path))

    agent_receipt = client.sign("tool", audit=False)
    server.close()

    with pytest.raises(RuntimeError, match="closed"):
        server.sign_bilateral(agent_receipt)


# ─── sign_authorized: chain= vs chain_json= API ───────────────────────────────


def _make_chain_for(agent, tmp_path):
    """Build a one-token delegation chain authorizing `agent`."""
    import json as _json
    import signet_auth

    owner = SigningAgent.create("auth-owner", signet_dir=str(tmp_path))
    scope = _json.dumps(
        {"tools": ["*"], "targets": ["*"], "max_depth": 0}
    )
    token_json = signet_auth.sign_delegation(
        owner._secret_key,
        owner.name,
        agent.public_key,
        agent.name,
        scope,
    )
    return owner, [_json.loads(token_json)]


def test_sign_authorized_with_chain_list(tmp_path):
    """chain= as list[dict] should work (preferred)."""
    agent = SigningAgent.create("auth-bot-1", signet_dir=str(tmp_path))
    _, chain = _make_chain_for(agent, tmp_path)

    receipt_json = agent.sign_authorized(
        "Bash",
        params={"cmd": "ls"},
        target="mcp://local",
        chain=chain,
    )
    import json as _json
    receipt = _json.loads(receipt_json)
    assert receipt["v"] == 4
    assert receipt["action"]["tool"] == "Bash"


def test_sign_authorized_with_chain_string(tmp_path):
    """chain= as JSON string should still work for backward compat."""
    import json as _json
    agent = SigningAgent.create("auth-bot-2", signet_dir=str(tmp_path))
    _, chain = _make_chain_for(agent, tmp_path)

    receipt_json = agent.sign_authorized(
        "Bash",
        chain=_json.dumps(chain),
    )
    assert _json.loads(receipt_json)["v"] == 4


def test_sign_authorized_with_chain_json_legacy(tmp_path):
    """chain_json= still works (deprecated)."""
    import json as _json
    agent = SigningAgent.create("auth-bot-3", signet_dir=str(tmp_path))
    _, chain = _make_chain_for(agent, tmp_path)

    receipt_json = agent.sign_authorized(
        "Bash",
        chain_json=_json.dumps(chain),
    )
    assert _json.loads(receipt_json)["v"] == 4


def test_sign_authorized_neither_raises(tmp_path):
    """Neither chain nor chain_json provided → TypeError."""
    agent = SigningAgent.create("auth-bot-4", signet_dir=str(tmp_path))
    with pytest.raises(TypeError, match="chain"):
        agent.sign_authorized("Bash")


def test_sign_authorized_both_raises(tmp_path):
    """Both chain and chain_json provided → TypeError."""
    import json as _json
    agent = SigningAgent.create("auth-bot-5", signet_dir=str(tmp_path))
    _, chain = _make_chain_for(agent, tmp_path)
    chain_json = _json.dumps(chain)

    with pytest.raises(TypeError, match="not both"):
        agent.sign_authorized("Bash", chain=chain, chain_json=chain_json)


def test_sign_authorized_after_close(tmp_path):
    """Closed agent raises RuntimeError."""
    agent = SigningAgent.create("auth-bot-6", signet_dir=str(tmp_path))
    _, chain = _make_chain_for(agent, tmp_path)
    agent.close()
    with pytest.raises(RuntimeError, match="closed"):
        agent.sign_authorized("Bash", chain=chain)
