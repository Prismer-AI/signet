import pytest
import signet_auth


def test_validate_key_name_valid():
    signet_auth.validate_key_name("my-agent_01")


def test_validate_key_name_invalid():
    with pytest.raises(signet_auth.InvalidNameError):
        signet_auth.validate_key_name("bad name!")


def test_default_signet_dir(monkeypatch):
    monkeypatch.delenv("SIGNET_HOME", raising=False)
    d = signet_auth.default_signet_dir()
    assert d.endswith(".signet")


def test_default_signet_dir_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path))
    assert signet_auth.default_signet_dir() == str(tmp_path)


def test_generate_and_save(tmp_path):
    info = signet_auth.generate_and_save(str(tmp_path), "alice", owner="Alice")
    assert info.name == "alice"
    assert info.owner == "Alice"
    assert isinstance(info.pubkey, str)
    assert isinstance(info.created_at, str)


def test_generate_and_save_no_owner(tmp_path):
    info = signet_auth.generate_and_save(str(tmp_path), "bob")
    assert info.name == "bob"
    assert info.owner is None


def test_generate_and_save_duplicate(tmp_path):
    signet_auth.generate_and_save(str(tmp_path), "dup")
    with pytest.raises(signet_auth.KeyExistsError):
        signet_auth.generate_and_save(str(tmp_path), "dup")


def test_generate_and_save_with_passphrase(tmp_path):
    info = signet_auth.generate_and_save(str(tmp_path), "enc", passphrase="secret")
    assert info.name == "enc"


def test_load_signing_key(tmp_path):
    signet_auth.generate_and_save(str(tmp_path), "loader")
    key = signet_auth.load_signing_key(str(tmp_path), "loader")
    assert isinstance(key, str)
    assert len(key) == 88  # 64-byte keypair, base64 encoded


def test_load_signing_key_encrypted(tmp_path):
    signet_auth.generate_and_save(str(tmp_path), "enc2", passphrase="pass")
    key = signet_auth.load_signing_key(str(tmp_path), "enc2", passphrase="pass")
    assert isinstance(key, str)


def test_load_signing_key_wrong_passphrase(tmp_path):
    signet_auth.generate_and_save(str(tmp_path), "enc3", passphrase="correct")
    with pytest.raises(signet_auth.DecryptionError):
        signet_auth.load_signing_key(str(tmp_path), "enc3", passphrase="wrong")


def test_load_signing_key_not_found(tmp_path):
    with pytest.raises(signet_auth.KeyNotFoundError):
        signet_auth.load_signing_key(str(tmp_path), "nope")


def test_load_verifying_key(tmp_path):
    signet_auth.generate_and_save(str(tmp_path), "vk")
    key = signet_auth.load_verifying_key(str(tmp_path), "vk")
    assert isinstance(key, str)
    assert len(key) == 44  # 32-byte verifying key, base64 encoded


def test_load_key_info(tmp_path):
    signet_auth.generate_and_save(str(tmp_path), "info", owner="InfoOwner")
    info = signet_auth.load_key_info(str(tmp_path), "info")
    assert info.name == "info"
    assert info.owner == "InfoOwner"


def test_list_keys(tmp_path):
    signet_auth.generate_and_save(str(tmp_path), "charlie")
    signet_auth.generate_and_save(str(tmp_path), "alice")
    signet_auth.generate_and_save(str(tmp_path), "bob")
    keys = signet_auth.list_keys(str(tmp_path))
    assert len(keys) == 3
    assert keys[0].name == "alice"
    assert keys[1].name == "bob"
    assert keys[2].name == "charlie"


def test_list_keys_empty(tmp_path):
    keys = signet_auth.list_keys(str(tmp_path))
    assert keys == []


def test_export_public_key(tmp_path):
    signet_auth.generate_and_save(str(tmp_path), "exp", owner="Exp")
    pub = signet_auth.export_public_key(str(tmp_path), "exp")
    assert isinstance(pub, dict)
    assert pub["name"] == "exp"
    assert pub["owner"] == "Exp"
    assert pub["algorithm"] == "ed25519"
    assert pub["v"] == 1


def test_sign_verify_roundtrip_with_saved_key(tmp_path):
    signet_auth.generate_and_save(str(tmp_path), "e2e")
    sk = signet_auth.load_signing_key(str(tmp_path), "e2e")
    vk = signet_auth.load_verifying_key(str(tmp_path), "e2e")
    action = signet_auth.Action("test_tool", params={"x": 1})
    receipt = signet_auth.sign(sk, action, "e2e", "owner")
    assert signet_auth.verify(receipt, vk) is True


def test_export_public_key_not_found(tmp_path):
    with pytest.raises(signet_auth.KeyNotFoundError):
        signet_auth.export_public_key(str(tmp_path), "nonexistent")
