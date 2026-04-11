import json

import pytest
import signet_auth


ALLOW_POLICY_YAML = """
version: 1
name: test-allow
rules:
  - id: allow-read
    match:
      tool: Read
    action: allow
"""

DENY_POLICY_YAML = """
version: 1
name: test-deny
default_action: deny
rules: []
"""

APPROVAL_POLICY_YAML = """
version: 1
name: test-approval
rules:
  - id: needs-approval
    match:
      tool: Write
    action: require_approval
    reason: write requires approval
"""

MIXED_POLICY_YAML = """
version: 1
name: mixed-policy
rules:
  - id: deny-rm
    match:
      tool: Bash
      params:
        command:
          contains: "rm -rf"
    action: deny
    reason: destructive command
  - id: allow-read
    match:
      tool: Read
    action: allow
"""


def _action_json(tool="Read", params=None, target="mcp://local"):
    action = {
        "tool": tool,
        "params": params or {},
        "params_hash": "",
        "target": target,
        "transport": "stdio",
    }
    return json.dumps(action)


# ─── parse_policy_yaml / parse_policy_json ───────────────────────────────────


def test_parse_policy_yaml():
    policy_json = signet_auth.parse_policy_yaml(ALLOW_POLICY_YAML)
    policy = json.loads(policy_json)
    assert policy["name"] == "test-allow"
    assert policy["version"] == 1
    assert len(policy["rules"]) == 1
    assert policy["rules"][0]["id"] == "allow-read"


def test_parse_policy_json():
    policy_data = {"version": 1, "name": "json-policy", "rules": []}
    policy_json = signet_auth.parse_policy_json(json.dumps(policy_data))
    policy = json.loads(policy_json)
    assert policy["name"] == "json-policy"


def test_parse_policy_yaml_invalid():
    with pytest.raises(signet_auth.PolicyParseError):
        signet_auth.parse_policy_yaml("not: valid: yaml: [[[")


def test_parse_policy_json_invalid():
    with pytest.raises(Exception):
        signet_auth.parse_policy_json("{invalid json")


# ─── compute_policy_hash ─────────────────────────────────────────────────────


def test_compute_policy_hash():
    policy_json = signet_auth.parse_policy_yaml(ALLOW_POLICY_YAML)
    hash_val = signet_auth.compute_policy_hash(policy_json)
    assert hash_val.startswith("sha256:")
    assert len(hash_val) == 71  # "sha256:" + 64 hex chars


def test_compute_policy_hash_deterministic():
    policy_json = signet_auth.parse_policy_yaml(ALLOW_POLICY_YAML)
    h1 = signet_auth.compute_policy_hash(policy_json)
    h2 = signet_auth.compute_policy_hash(policy_json)
    assert h1 == h2


# ─── evaluate_policy ─────────────────────────────────────────────────────────


def test_evaluate_policy_allow():
    policy_json = signet_auth.parse_policy_yaml(ALLOW_POLICY_YAML)
    result_json = signet_auth.evaluate_policy(_action_json("Read"), "agent", policy_json)
    result = json.loads(result_json)
    assert result["decision"] == "allow"
    assert "allow-read" in result["matched_rules"]


def test_evaluate_policy_deny():
    policy_json = signet_auth.parse_policy_yaml(DENY_POLICY_YAML)
    result_json = signet_auth.evaluate_policy(_action_json("Bash"), "agent", policy_json)
    result = json.loads(result_json)
    assert result["decision"] == "deny"


def test_evaluate_policy_require_approval():
    policy_json = signet_auth.parse_policy_yaml(APPROVAL_POLICY_YAML)
    result_json = signet_auth.evaluate_policy(_action_json("Write"), "agent", policy_json)
    result = json.loads(result_json)
    assert result["decision"] == "require_approval"


def test_evaluate_policy_mixed_deny_wins():
    policy_json = signet_auth.parse_policy_yaml(MIXED_POLICY_YAML)
    action = _action_json("Bash", params={"command": "rm -rf /"})
    result_json = signet_auth.evaluate_policy(action, "agent", policy_json)
    result = json.loads(result_json)
    assert result["decision"] == "deny"
    assert "deny-rm" in result["matched_rules"]


def test_evaluate_policy_mixed_allow():
    policy_json = signet_auth.parse_policy_yaml(MIXED_POLICY_YAML)
    result_json = signet_auth.evaluate_policy(_action_json("Read"), "agent", policy_json)
    result = json.loads(result_json)
    assert result["decision"] == "allow"


# ─── sign_with_policy ────────────────────────────────────────────────────────


def test_sign_with_policy_allowed():
    kp = signet_auth.generate_keypair()
    policy_json = signet_auth.parse_policy_yaml(ALLOW_POLICY_YAML)
    action = _action_json("Read")

    receipt_json, eval_json = signet_auth.sign_with_policy(
        kp.secret_key, action, "agent", "owner", policy_json,
    )
    receipt = json.loads(receipt_json)
    eval_result = json.loads(eval_json)

    assert receipt["v"] == 1
    assert receipt["policy"] is not None
    assert receipt["policy"]["policy_name"] == "test-allow"
    assert receipt["policy"]["decision"] == "allow"
    assert receipt["policy"]["policy_hash"].startswith("sha256:")
    assert eval_result["decision"] == "allow"


def test_sign_with_policy_denied():
    kp = signet_auth.generate_keypair()
    policy_json = signet_auth.parse_policy_yaml(DENY_POLICY_YAML)
    action = _action_json("Bash")

    with pytest.raises(signet_auth.PolicyViolationError):
        signet_auth.sign_with_policy(kp.secret_key, action, "agent", "owner", policy_json)


def test_sign_with_policy_require_approval():
    kp = signet_auth.generate_keypair()
    policy_json = signet_auth.parse_policy_yaml(APPROVAL_POLICY_YAML)
    action = _action_json("Write")

    with pytest.raises(signet_auth.RequiresApprovalError):
        signet_auth.sign_with_policy(kp.secret_key, action, "agent", "owner", policy_json)


def test_sign_with_policy_receipt_verifiable():
    kp = signet_auth.generate_keypair()
    policy_json = signet_auth.parse_policy_yaml(ALLOW_POLICY_YAML)
    action = _action_json("Read")

    receipt_json, _ = signet_auth.sign_with_policy(
        kp.secret_key, action, "agent", "owner", policy_json,
    )
    receipt = signet_auth.Receipt.from_json(receipt_json)
    assert signet_auth.verify(receipt, kp.public_key) is True


def test_sign_with_policy_tampered_attestation_fails():
    kp = signet_auth.generate_keypair()
    policy_json = signet_auth.parse_policy_yaml(ALLOW_POLICY_YAML)
    action = _action_json("Read")

    receipt_json, _ = signet_auth.sign_with_policy(
        kp.secret_key, action, "agent", "owner", policy_json,
    )
    # Tamper with policy name
    tampered = receipt_json.replace('"test-allow"', '"forged-policy"')
    receipt = signet_auth.Receipt.from_json(tampered)
    assert signet_auth.verify(receipt, kp.public_key) is False


def test_sign_with_policy_invalid_key():
    policy_json = signet_auth.parse_policy_yaml(ALLOW_POLICY_YAML)
    action = _action_json("Read")
    with pytest.raises(signet_auth.InvalidKeyError):
        signet_auth.sign_with_policy("bad-key", action, "agent", "owner", policy_json)


def test_sign_with_policy_no_policy_backward_compat():
    """Receipts signed without policy (regular sign) still verify."""
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Read", params={})
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    # Regular sign produces receipts without policy field
    receipt_json = receipt.to_json()
    receipt_data = json.loads(receipt_json)
    assert receipt_data.get("policy") is None
    assert signet_auth.verify(receipt, kp.public_key) is True
