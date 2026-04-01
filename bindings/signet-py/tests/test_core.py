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
