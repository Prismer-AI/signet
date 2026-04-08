import pytest
import signet_auth


def test_exception_hierarchy():
    assert issubclass(signet_auth.InvalidKeyError, signet_auth.SignetError)
    assert issubclass(signet_auth.SignatureMismatchError, signet_auth.SignetError)
    assert issubclass(signet_auth.InvalidReceiptError, signet_auth.SignetError)
    assert issubclass(signet_auth.CanonicalizeError, signet_auth.SignetError)
    assert issubclass(signet_auth.SerializeError, signet_auth.SignetError)
    assert issubclass(signet_auth.KeyNotFoundError, signet_auth.SignetError)
    assert issubclass(signet_auth.KeyExistsError, signet_auth.SignetError)
    assert issubclass(signet_auth.InvalidNameError, signet_auth.SignetError)
    assert issubclass(signet_auth.DecryptionError, signet_auth.SignetError)
    assert issubclass(signet_auth.CorruptedFileError, signet_auth.SignetError)
    assert issubclass(signet_auth.UnsupportedFormatError, signet_auth.SignetError)
    assert issubclass(signet_auth.CorruptedRecordError, signet_auth.SignetError)
    assert issubclass(signet_auth.SignetIOError, signet_auth.SignetError)


def test_signet_error_is_exception():
    assert issubclass(signet_auth.SignetError, Exception)


def test_action_constructor():
    action = signet_auth.Action("github_create_issue", params={"title": "bug"})
    assert action.tool == "github_create_issue"
    assert action.params == {"title": "bug"}
    assert action.target == ""
    assert action.transport == "stdio"


def test_action_defaults():
    action = signet_auth.Action("test_tool")
    assert action.params is None
    assert action.target == ""
    assert action.transport == "stdio"


def test_action_hash_only():
    action = signet_auth.Action.hash_only("test_tool", "sha256:abc123")
    assert action.tool == "test_tool"
    assert action.params is None
    assert action.params_hash == "sha256:abc123"


def test_action_params_types():
    signet_auth.Action("t", params=["a", "b"])
    signet_auth.Action("t", params="string")
    signet_auth.Action("t", params=42)
    signet_auth.Action("t", params=True)


def test_generate_keypair():
    kp = signet_auth.generate_keypair()
    assert isinstance(kp, signet_auth.KeyPair)
    assert kp.secret_key != kp.public_key


def test_keypair_uniqueness():
    kp1 = signet_auth.generate_keypair()
    kp2 = signet_auth.generate_keypair()
    assert kp1.secret_key != kp2.secret_key


def test_sign_produces_receipt():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool", params={"key": "val"})
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    assert isinstance(receipt, signet_auth.Receipt)
    assert receipt.v == 1
    assert receipt.id.startswith("rec_")
    assert receipt.sig.startswith("ed25519:")
    assert receipt.nonce.startswith("rnd_")
    assert receipt.signer.name == "agent"
    assert receipt.signer.owner == "owner"
    assert receipt.action.tool == "test_tool"


def test_sign_owner_none_normalizes():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool")
    receipt = signet_auth.sign(kp.secret_key, action, "agent")
    assert receipt.signer.owner == ""


def test_sign_hash_only_mode():
    kp = signet_auth.generate_keypair()
    valid_hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    action = signet_auth.Action.hash_only("test_tool", valid_hash)
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    assert receipt.action.params_hash == valid_hash


def test_verify_valid():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool", params={"k": "v"})
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    assert signet_auth.verify(receipt, kp.public_key) is True


def test_verify_wrong_key():
    kp1 = signet_auth.generate_keypair()
    kp2 = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool")
    receipt = signet_auth.sign(kp1.secret_key, action, "agent", "owner")
    assert signet_auth.verify(receipt, kp2.public_key) is False


def test_verify_malformed_key_raises():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool")
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    with pytest.raises(signet_auth.InvalidKeyError):
        signet_auth.verify(receipt, "not-valid-base64!!!")


def test_verify_tampered_receipt():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool")
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    json_str = receipt.to_json()
    tampered = json_str.replace('"agent"', '"evil"')
    tampered_receipt = signet_auth.Receipt.from_json(tampered)
    assert signet_auth.verify(tampered_receipt, kp.public_key) is False


def test_keypair_repr_redacts_secret():
    kp = signet_auth.generate_keypair()
    assert "REDACTED" in repr(kp)
    assert kp.secret_key not in repr(kp)


def test_receipt_to_from_json():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool", params={"key": "value"})
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    json_str = receipt.to_json()
    restored = signet_auth.Receipt.from_json(json_str)
    assert restored.id == receipt.id
    assert restored.action.tool == "test_tool"
    assert restored.signer.name == "agent"
    assert restored.sig == receipt.sig


def test_sign_invalid_secret_key():
    action = signet_auth.Action("test_tool")
    with pytest.raises(signet_auth.InvalidKeyError):
        signet_auth.sign("not-valid-base64!!!", action, "agent", "owner")


def test_sign_wrong_length_secret_key():
    import base64
    short_key = base64.b64encode(b"tooshort").decode()
    action = signet_auth.Action("test_tool")
    with pytest.raises(signet_auth.InvalidKeyError):
        signet_auth.sign(short_key, action, "agent", "owner")


def test_receipt_from_json_invalid():
    with pytest.raises((signet_auth.InvalidReceiptError, signet_auth.SerializeError)):
        signet_auth.Receipt.from_json("not valid json")
