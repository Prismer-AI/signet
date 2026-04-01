"""signet-auth: Cryptographic action receipts for AI agents."""

from signet_auth._signet import (
    __version__,
    # Exceptions
    SignetError,
    InvalidKeyError,
    SignatureMismatchError,
    InvalidReceiptError,
    CanonicalizeError,
    SerializeError,
    KeyNotFoundError,
    KeyExistsError,
    InvalidNameError,
    DecryptionError,
    CorruptedFileError,
    CorruptedRecordError,
    SignetIOError,
    UnsupportedFormatError,
    # Types
    Action,
    Signer,
    Receipt,
    KeyPair,
    KeyInfo,
    AuditRecord,
    ChainBreak,
    ChainStatus,
    VerifyFailure,
    VerifyResult,
    # Core functions
    generate_keypair,
    sign,
    verify,
)

__all__ = [
    "__version__",
    # Exceptions
    "SignetError",
    "InvalidKeyError",
    "SignatureMismatchError",
    "InvalidReceiptError",
    "CanonicalizeError",
    "SerializeError",
    "KeyNotFoundError",
    "KeyExistsError",
    "InvalidNameError",
    "DecryptionError",
    "CorruptedFileError",
    "CorruptedRecordError",
    "SignetIOError",
    "UnsupportedFormatError",
    # Types
    "Action",
    "Signer",
    "Receipt",
    "KeyPair",
    "KeyInfo",
    "AuditRecord",
    "ChainBreak",
    "ChainStatus",
    "VerifyFailure",
    "VerifyResult",
    # Core functions
    "generate_keypair",
    "sign",
    "verify",
]
