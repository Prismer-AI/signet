"""ComplianceBackend Protocol adapter for LangChain.

Implements the ComplianceBackend Protocol proposed in langchain-ai/langchain#35691.
Wraps SigningAgent to produce receipts compatible with the pluggable compliance
callback interface.

Usage:
    from signet_auth.compliance_backend import SignetComplianceBackend
    from langchain.callbacks import ComplianceCallbackHandler  # once available

    backend = SignetComplianceBackend.create("my-agent")
    handler = ComplianceCallbackHandler(backend=backend)
    chain.invoke(input, config={"callbacks": [handler]})

Note: This module is forward-looking — the ComplianceBackend Protocol is
being drafted at github.com/aniketh-maddipati/agentmint. This adapter
will be updated once the spec is finalized.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from signet_auth.agent import SigningAgent


@dataclass
class ToolEvent:
    """Minimal tool event structure matching the draft Protocol."""
    tool_name: str
    params: dict = field(default_factory=dict)
    run_id: str = ""
    timestamp: str = ""
    parent_run_id: Optional[str] = None


@dataclass
class ComplianceReceipt:
    """Receipt structure matching the draft Protocol schema."""
    event_ref: str           # run_id + tool_name + timestamp
    signature: str           # ed25519:<base64>
    chain_ref: str           # parent receipt hash for tamper-evident chain
    backend_id: str          # "signet-v0.9"
    signer_pubkey: str       # ed25519 public key
    params_hash: str         # sha256 of canonical params
    policy_ref: Optional[str] = None  # policy hash + rule + decision
    exp: Optional[str] = None         # optional expiration (RFC 3339)
    raw_receipt: Optional[dict] = None  # full Signet receipt for backends that want it


class SignetComplianceBackend:
    """Signet implementation of the ComplianceBackend Protocol.

    Produces Ed25519-signed, hash-chained receipts for every tool call.
    Offline-verifiable, no external service required.
    """

    BACKEND_ID = "signet-v0.9"

    def __init__(self, agent: SigningAgent):
        self._agent = agent
        self._last_receipt_id: Optional[str] = None

    @classmethod
    def create(cls, key_name: str = "langchain-agent", owner: str = "") -> "SignetComplianceBackend":
        """Create a backend with a new or existing SigningAgent."""
        try:
            agent = SigningAgent(key_name)
        except Exception:
            agent = SigningAgent.create(key_name, owner=owner)
        return cls(agent)

    def notarize(self, event: ToolEvent) -> ComplianceReceipt:
        """Sign a tool event and return a compliance receipt."""
        receipt = self._agent.sign(
            event.tool_name,
            params=event.params,
            audit=True,
        )

        receipt_json = receipt.to_json()
        receipt_data = json.loads(receipt_json)

        event_ref = f"{event.run_id}:{event.tool_name}:{receipt_data.get('ts', '')}"
        chain_ref = self._last_receipt_id or ""
        self._last_receipt_id = receipt_data.get("id", "")

        policy_data = receipt_data.get("policy")
        policy_ref = None
        if policy_data:
            policy_ref = f"{policy_data.get('policy_hash', '')}:{policy_data.get('matched_rules', [])}:{policy_data.get('decision', '')}"

        return ComplianceReceipt(
            event_ref=event_ref,
            signature=receipt_data.get("sig", ""),
            chain_ref=chain_ref,
            backend_id=self.BACKEND_ID,
            signer_pubkey=receipt_data.get("signer", {}).get("pubkey", ""),
            params_hash=receipt_data.get("action", {}).get("params_hash", ""),
            policy_ref=policy_ref,
            exp=receipt_data.get("exp"),
            raw_receipt=receipt_data,
        )

    def verify(self, receipt: ComplianceReceipt) -> bool:
        """Verify a compliance receipt's signature."""
        if receipt.raw_receipt is None:
            return False
        try:
            from signet_auth._signet import Receipt as PyReceipt, verify as _verify
            py_receipt = PyReceipt.from_json(json.dumps(receipt.raw_receipt))
            pubkey = receipt.signer_pubkey
            if pubkey.startswith("ed25519:"):
                pubkey = pubkey[len("ed25519:"):]
            return _verify(py_receipt, pubkey)
        except Exception:
            return False
