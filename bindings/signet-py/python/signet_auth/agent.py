from __future__ import annotations

from datetime import datetime
from typing import Any

import json as _json

from signet_auth._signet import (
    Action,
    AuditRecord,
    BilateralReceipt,
    ChainStatus,
    KeyInfo,
    Receipt,
    VerifyResult,
    audit_append,
    audit_append_encrypted,
    audit_query as _audit_query,
    audit_verify_chain as _audit_verify_chain,
    audit_verify_signatures as _audit_verify_signatures,
    default_signet_dir,
    generate_and_save,
    load_key_info,
    load_signing_key,
    load_verifying_key,
    sign as _sign,
    sign_bilateral as _sign_bilateral,
    sign_delegation as _sign_delegation,
    sign_authorized as _sign_authorized,
    verify as _verify,
    verify_authorized as _verify_authorized,
    verify_bilateral as _verify_bilateral,
    verify_delegation as _verify_delegation,
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
        self._passphrase = passphrase
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
        audit_encrypt_params: bool = False,
    ) -> Receipt:
        """Sign an action.

        If audit=True, appends to audit log after signing.
        Audit append failures raise the underlying SignetError.
        """
        if self._secret_key is None:
            raise RuntimeError("SigningAgent has been closed")
        if audit_encrypt_params and not audit:
            raise ValueError("audit_encrypt_params requires audit=True")
        action = Action(tool, params=params, target=target, transport=transport)
        owner = self._key_info.owner or ""
        receipt = _sign(self._secret_key, action, self._name, owner)
        if audit:
            if audit_encrypt_params:
                audit_append_encrypted(self._signet_dir, receipt, self._secret_key)
            else:
                audit_append(self._signet_dir, receipt)
        return receipt

    def delegate(
        self,
        delegate_pubkey: str,
        delegate_name: str,
        *,
        tools: list[str] | None = None,
        targets: list[str] | None = None,
        max_depth: int = 0,
        expires: str | None = None,
    ) -> str:
        """Create a delegation token granting scoped authority to another agent.

        Args:
            delegate_pubkey: Base64-encoded Ed25519 public key of the delegate.
            delegate_name: Display name of the delegate agent.
            tools: Allowed tool names, or None for wildcard ["*"].
            targets: Allowed targets, or None for wildcard ["*"].
            max_depth: How many levels the delegate can re-delegate. 0 = cannot.
            expires: Optional RFC 3339 expiry (e.g. "2026-12-31T23:59:59Z").

        Returns:
            JSON string of the signed DelegationToken.
        """
        if self._secret_key is None:
            raise RuntimeError("SigningAgent has been closed")
        scope = {
            "tools": tools or ["*"],
            "targets": targets or ["*"],
            "max_depth": max_depth,
        }
        if expires is not None:
            scope["expires"] = expires
        return _sign_delegation(
            self._secret_key,
            self._name,
            delegate_pubkey,
            delegate_name,
            _json.dumps(scope),
        )

    def sign_authorized(
        self,
        tool: str,
        params: Any | None = None,
        target: str = "",
        transport: str = "stdio",
        *,
        chain_json: str,
    ) -> str:
        """Sign an action with a delegation chain (produces v4 receipt).

        Args:
            tool: Tool name.
            params: Tool parameters.
            target: Target URI.
            transport: Transport type.
            chain_json: JSON string of the delegation chain array.

        Returns:
            JSON string of the v4 Receipt.
        """
        if self._secret_key is None:
            raise RuntimeError("SigningAgent has been closed")
        action = {
            "tool": tool,
            "params": params if params is not None else {},
            "params_hash": "",
            "target": target,
            "transport": transport,
        }
        return _sign_authorized(
            self._secret_key,
            _json.dumps(action),
            self._name,
            chain_json,
        )

    @staticmethod
    def verify_delegation(token_json: str) -> bool:
        """Verify a delegation token's signature."""
        return _verify_delegation(token_json)

    @staticmethod
    def verify_authorized(
        receipt_json: str,
        trusted_roots: list[str],
        clock_skew_secs: int = 60,
    ) -> str:
        """Verify an authorized (v4) receipt against trusted root keys.

        Args:
            receipt_json: JSON string of the v4 receipt.
            trusted_roots: List of base64-encoded root public keys.
            clock_skew_secs: Clock skew tolerance in seconds.

        Returns:
            JSON string of the effective Scope.
        """
        return _verify_authorized(receipt_json, trusted_roots, clock_skew_secs)

    def close(self) -> None:
        """Drop references to secret key material.

        Note: Python strings are immutable and may remain in memory
        until garbage collected. This method drops the reference
        to minimize the exposure window.
        """
        self._secret_key = None

    def __enter__(self) -> "SigningAgent":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def sign_bilateral(
        self,
        agent_receipt: Receipt,
        response_content: Any = None,
    ) -> BilateralReceipt:
        """Co-sign an agent's receipt as a server.

        Use this when this agent acts as a server verifying and co-signing
        another agent's tool call receipt, creating a bilateral receipt
        where both sides have cryptographic proof.

        Args:
            agent_receipt: The unilateral (dispatch) receipt from the calling agent.
            response_content: The response data to bind into the receipt.
                Defaults to ``{}`` if None.
        """
        if self._secret_key is None:
            raise RuntimeError("SigningAgent has been closed")
        return _sign_bilateral(
            self._secret_key,
            agent_receipt,
            response_content if response_content is not None else {},
            self._name,
        )

    def verify(self, receipt: Receipt) -> bool:
        """Verify a receipt against this agent's public key."""
        return _verify(receipt, self._public_key)

    def verify_bilateral_receipt(
        self,
        receipt: BilateralReceipt,
    ) -> bool:
        """Verify a bilateral receipt against this agent's public key (as server)."""
        return _verify_bilateral(receipt, self._public_key)

    @staticmethod
    def verify_bilateral_with_key(receipt: BilateralReceipt, server_public_key: str) -> bool:
        """Verify a bilateral receipt against any server public key."""
        return _verify_bilateral(receipt, server_public_key)

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
        decrypt_params: bool = False,
    ) -> list[AuditRecord]:
        """Query this agent's audit log (signer auto-filtered to self.name)."""
        return _audit_query(
            self._signet_dir,
            since=since,
            tool=tool,
            signer=self._name,
            limit=limit,
            decrypt_params=decrypt_params,
            passphrase=self._passphrase,
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
        trusted_agent_keys: list[str] | None = None,
        trusted_server_keys: list[str] | None = None,
    ) -> VerifyResult:
        """Verify signatures on this agent's audit records."""
        return _audit_verify_signatures(
            self._signet_dir,
            since=since,
            tool=tool,
            signer=self._name,
            limit=limit,
            trusted_agent_keys=trusted_agent_keys,
            trusted_server_keys=trusted_server_keys,
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
