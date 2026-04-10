import json

import pytest
import signet_auth


def _make_scope(**overrides):
    scope = {"tools": ["Bash", "Read"], "targets": ["mcp://github.local"], "max_depth": 1}
    scope.update(overrides)
    return json.dumps(scope)


def _make_keypair():
    return signet_auth.generate_keypair()


# ─── sign_delegation / verify_delegation ─────────────────────────────────────


def test_sign_delegation_roundtrip():
    owner = _make_keypair()
    agent = _make_keypair()
    scope = _make_scope()

    token_json = signet_auth.sign_delegation(
        owner.secret_key, "alice", agent.public_key, "bot", scope,
    )
    assert signet_auth.verify_delegation(token_json) is True


def test_delegation_token_fields():
    owner = _make_keypair()
    agent = _make_keypair()
    scope = _make_scope()

    token_json = signet_auth.sign_delegation(
        owner.secret_key, "alice", agent.public_key, "bot", scope,
    )
    token = json.loads(token_json)
    assert token["v"] == 1
    assert token["delegator"]["name"] == "alice"
    assert token["delegate"]["name"] == "bot"
    assert token["scope"]["tools"] == ["Bash", "Read"]
    assert token["scope"]["targets"] == ["mcp://github.local"]
    assert token["scope"]["max_depth"] == 1
    assert token["sig"].startswith("ed25519:")
    assert token["id"].startswith("del_") or len(token["id"]) > 0


def test_delegation_tampered_sig():
    owner = _make_keypair()
    agent = _make_keypair()
    scope = _make_scope()

    token_json = signet_auth.sign_delegation(
        owner.secret_key, "alice", agent.public_key, "bot", scope,
    )
    tampered = token_json.replace('"alice"', '"evil"')
    assert signet_auth.verify_delegation(tampered) is False


def test_delegation_invalid_delegator_key():
    agent = _make_keypair()
    scope = _make_scope()
    with pytest.raises(signet_auth.InvalidKeyError):
        signet_auth.sign_delegation("not-valid-base64!", "alice", agent.public_key, "bot", scope)


def test_delegation_invalid_delegate_key():
    owner = _make_keypair()
    scope = _make_scope()
    with pytest.raises(signet_auth.InvalidKeyError):
        signet_auth.sign_delegation(owner.secret_key, "alice", "garbage", "bot", scope)


def test_delegation_empty_tools_rejected():
    owner = _make_keypair()
    agent = _make_keypair()
    scope = _make_scope(tools=[])
    with pytest.raises(signet_auth.SignetError):
        signet_auth.sign_delegation(owner.secret_key, "alice", agent.public_key, "bot", scope)


def test_delegation_empty_targets_rejected():
    owner = _make_keypair()
    agent = _make_keypair()
    scope = _make_scope(targets=[])
    with pytest.raises(signet_auth.SignetError):
        signet_auth.sign_delegation(owner.secret_key, "alice", agent.public_key, "bot", scope)


def test_delegation_empty_name_rejected():
    owner = _make_keypair()
    agent = _make_keypair()
    scope = _make_scope()
    with pytest.raises(signet_auth.SignetError):
        signet_auth.sign_delegation(owner.secret_key, "", agent.public_key, "bot", scope)
    with pytest.raises(signet_auth.SignetError):
        signet_auth.sign_delegation(owner.secret_key, "alice", agent.public_key, "", scope)


def test_delegation_with_parent_scope_narrowing():
    owner = _make_keypair()
    agent = _make_keypair()
    parent_scope = _make_scope(tools=["Bash", "Read", "Write"], max_depth=2)
    child_scope = _make_scope(tools=["Bash", "Read"], max_depth=1)

    token_json = signet_auth.sign_delegation(
        owner.secret_key, "alice", agent.public_key, "bot",
        child_scope, parent_scope_json=parent_scope,
    )
    assert signet_auth.verify_delegation(token_json) is True


def test_delegation_scope_widening_rejected():
    owner = _make_keypair()
    agent = _make_keypair()
    parent_scope = _make_scope(tools=["Read"], max_depth=1)
    child_scope = _make_scope(tools=["Bash", "Read"], max_depth=1)

    with pytest.raises(signet_auth.SignetError):
        signet_auth.sign_delegation(
            owner.secret_key, "alice", agent.public_key, "bot",
            child_scope, parent_scope_json=parent_scope,
        )


def test_delegation_invalid_json():
    with pytest.raises(Exception):
        signet_auth.verify_delegation("{not valid json")


# ─── sign_authorized / verify_authorized (v4 receipts) ──────────────────────


def _make_delegation_chain():
    """Create owner -> agent delegation and return (owner_kp, agent_kp, chain_json)."""
    owner = _make_keypair()
    agent = _make_keypair()
    scope = _make_scope(tools=["*"], targets=["*"], max_depth=0)

    token_json = signet_auth.sign_delegation(
        owner.secret_key, "alice", agent.public_key, "bot", scope,
    )
    chain_json = json.dumps([json.loads(token_json)])
    return owner, agent, chain_json


def test_sign_authorized_roundtrip():
    owner, agent, chain_json = _make_delegation_chain()
    action = {"tool": "Bash", "params": {"command": "ls"}, "params_hash": "", "target": "mcp://local", "transport": "stdio"}
    action_json = json.dumps(action)

    receipt_json = signet_auth.sign_authorized(agent.secret_key, action_json, "bot", chain_json)
    # verify_authorized returns the effective scope JSON on success, raises on failure
    scope_json = signet_auth.verify_authorized(receipt_json, [owner.public_key])
    scope = json.loads(scope_json)
    assert "tools" in scope


def test_authorized_receipt_is_v4():
    owner, agent, chain_json = _make_delegation_chain()
    action = {"tool": "Bash", "params": {}, "params_hash": "", "target": "mcp://local", "transport": "stdio"}
    action_json = json.dumps(action)

    receipt_json = signet_auth.sign_authorized(agent.secret_key, action_json, "bot", chain_json)
    receipt = json.loads(receipt_json)
    assert receipt["v"] == 4
    assert "authorization" in receipt


def test_authorized_wrong_root_key():
    owner, agent, chain_json = _make_delegation_chain()
    other = _make_keypair()
    action = {"tool": "Bash", "params": {}, "params_hash": "", "target": "mcp://local", "transport": "stdio"}
    action_json = json.dumps(action)

    receipt_json = signet_auth.sign_authorized(agent.secret_key, action_json, "bot", chain_json)
    with pytest.raises(signet_auth.ChainError):
        signet_auth.verify_authorized(receipt_json, [other.public_key])


def test_authorized_tampered_action():
    owner, agent, chain_json = _make_delegation_chain()
    action = {"tool": "Bash", "params": {"command": "ls"}, "params_hash": "", "target": "mcp://local", "transport": "stdio"}
    action_json = json.dumps(action)

    receipt_json = signet_auth.sign_authorized(agent.secret_key, action_json, "bot", chain_json)
    tampered = receipt_json.replace('"ls"', '"rm -rf /"')
    with pytest.raises(signet_auth.SignatureMismatchError):
        signet_auth.verify_authorized(tampered, [owner.public_key])


def test_authorized_empty_chain_rejected():
    agent = _make_keypair()
    action = {"tool": "Bash", "params": {}, "params_hash": "", "target": "mcp://local", "transport": "stdio"}
    action_json = json.dumps(action)

    with pytest.raises(signet_auth.SignetError):
        signet_auth.sign_authorized(agent.secret_key, action_json, "bot", "[]")


def test_authorized_invalid_key():
    action = {"tool": "Bash", "params": {}, "params_hash": "", "target": "mcp://local", "transport": "stdio"}
    action_json = json.dumps(action)
    with pytest.raises(signet_auth.InvalidKeyError):
        signet_auth.sign_authorized("bad-key", action_json, "bot", "[]")
