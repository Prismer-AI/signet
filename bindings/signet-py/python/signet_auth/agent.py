from __future__ import annotations

from datetime import datetime
from typing import Any

from signet_auth._signet import (
    Action,
    AuditRecord,
    ChainStatus,
    KeyInfo,
    Receipt,
    VerifyResult,
    audit_append,
    audit_query as _audit_query,
    audit_verify_chain as _audit_verify_chain,
    audit_verify_signatures as _audit_verify_signatures,
    default_signet_dir,
    generate_and_save,
    load_key_info,
    load_signing_key,
    load_verifying_key,
    sign as _sign,
    verify as _verify,
)


class SigningAgent:
    """High-level wrapper: manages identity, signing, and audit."""

    def __init__(
        self,
        name: str,
        *,
        signet_dir: str | None = None,
        passphrase: str | None = None,
    ) -> None:
        """Load an existing key from signet_dir/keys/<name>.key.

        Owner is read from the .pub file, not passed as a parameter.
        Raises KeyNotFoundError if key doesn't exist.
        """
        self._signet_dir = signet_dir or default_signet_dir()
        self._name = name
        self._secret_key = load_signing_key(self._signet_dir, name, passphrase=passphrase)
        self._public_key = load_verifying_key(self._signet_dir, name)
        self._key_info = load_key_info(self._signet_dir, name)

    @classmethod
    def create(
        cls,
        name: str,
        *,
        owner: str | None = None,
        signet_dir: str | None = None,
        passphrase: str | None = None,
    ) -> SigningAgent:
        """Generate a new identity, persist to disk, and return an agent."""
        resolved_dir = signet_dir or default_signet_dir()
        generate_and_save(resolved_dir, name, owner=owner, passphrase=passphrase)
        return cls(name, signet_dir=signet_dir, passphrase=passphrase)

    def sign(
        self,
        tool: str,
        params: Any | None = None,
        target: str = "",
        transport: str = "stdio",
        *,
        audit: bool = True,
    ) -> Receipt:
        """Sign an action.

        If audit=True, appends to audit log after signing.
        Audit append failures raise the underlying SignetError.
        """
        if not self._secret_key:
            raise RuntimeError("SigningAgent has been closed")
        action = Action(tool, params=params, target=target, transport=transport)
        owner = self._key_info.owner or ""
        receipt = _sign(self._secret_key, action, self._name, owner)
        if audit:
            audit_append(self._signet_dir, receipt)
        return receipt

    def close(self) -> None:
        """Drop references to secret key material.

        Note: Python strings are immutable and may remain in memory
        until garbage collected. This method drops the reference
        to minimize the exposure window.
        """
        self._secret_key = ""

    def __enter__(self) -> "SigningAgent":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def verify(self, receipt: Receipt) -> bool:
        """Verify a receipt against this agent's public key."""
        return _verify(receipt, self._public_key)

    @staticmethod
    def verify_with_key(receipt: Receipt, public_key: str) -> bool:
        """Verify a receipt against any public key (base64)."""
        return _verify(receipt, public_key)

    def audit_query(
        self,
        *,
        since: str | datetime | None = None,
        tool: str | None = None,
        limit: int | None = None,
    ) -> list[AuditRecord]:
        """Query this agent's audit log (signer auto-filtered to self.name)."""
        return _audit_query(
            self._signet_dir,
            since=since,
            tool=tool,
            signer=self._name,
            limit=limit,
        )

    def audit_verify_chain(self) -> ChainStatus:
        """Verify the integrity of the audit hash chain."""
        return _audit_verify_chain(self._signet_dir)

    def audit_verify_signatures(
        self,
        *,
        since: str | datetime | None = None,
        tool: str | None = None,
        limit: int | None = None,
    ) -> VerifyResult:
        """Verify signatures on this agent's audit records."""
        return _audit_verify_signatures(
            self._signet_dir,
            since=since,
            tool=tool,
            signer=self._name,
            limit=limit,
        )

    @property
    def public_key(self) -> str:
        return self._public_key

    @property
    def name(self) -> str:
        return self._name

    @property
    def owner(self) -> str | None:
        return self._key_info.owner

    @property
    def key_info(self) -> KeyInfo:
        return self._key_info

    @property
    def signet_dir(self) -> str:
        return self._signet_dir
