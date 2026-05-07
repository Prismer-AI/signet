"""Server-side verification for MCP tool call requests."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from signet_auth._signet import Receipt, verify

CLOCK_SKEW_TOLERANCE_SECONDS = 30


class NonceChecker(Protocol):
    """Backend interface for replay protection on agent nonces.

    Compatible with `signet_core::verify::NonceChecker` (Rust trait).
    Implementations: `InMemoryNonceChecker`, `FileNonceChecker`,
    plus any custom Redis / SQL backend you care to write.

    `check_and_record` is the atomic primitive used by `verify_request`.
    Backends with multi-thread or multi-process exposure MUST implement
    it under a single critical section (lock, transaction). The default
    fallback in `verify_request` (is_replay → record) is racy.
    """

    def is_replay(self, nonce: str) -> bool:
        ...

    def record(self, nonce: str) -> None:
        ...

    def check_and_record(self, nonce: str) -> bool:
        """Atomically check + record a nonce.

        Returns True if the nonce was fresh (and is now recorded), or
        False if it had been seen before.
        """
        ...


class InMemoryNonceChecker:
    """Process-local nonce checker. Suitable for unit tests and demos.

    Lost on process restart — for pilots, use FileNonceChecker.
    """

    def __init__(self, max_entries: int = 10_000, ttl_secs: int = 3600) -> None:
        self._seen: dict[str, datetime] = {}
        self._lock = threading.Lock()
        self._max = max_entries
        self._ttl = timedelta(seconds=ttl_secs)

    def _sweep(self, now: datetime) -> None:
        cutoff = now - self._ttl
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

    def is_replay(self, nonce: str) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._sweep(now)
            return nonce in self._seen

    def record(self, nonce: str) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._sweep(now)
            if len(self._seen) >= self._max:
                oldest = min(self._seen, key=self._seen.get)  # type: ignore[arg-type]
                self._seen.pop(oldest, None)
            self._seen[nonce] = now

    def check_and_record(self, nonce: str) -> bool:
        """Atomic under self._lock — single critical section."""
        now = datetime.now(timezone.utc)
        with self._lock:
            self._sweep(now)
            if nonce in self._seen:
                return False
            if len(self._seen) >= self._max:
                oldest = min(self._seen, key=self._seen.get)  # type: ignore[arg-type]
                self._seen.pop(oldest, None)
            self._seen[nonce] = now
            return True


class FileNonceChecker:
    """JSON file-backed nonce checker. Survives process restarts.

    Single-host pilot grade. Writes are atomic on POSIX (write to temp +
    rename) and serialized via a process-local lock — concurrent writers
    on the same path may still race, but each individual write is
    consistent and the worst case is brief over-retention of a nonce.

    For multi-host or HA, use a Redis or SQL backend instead.
    """

    def __init__(
        self,
        path: str | Path,
        max_entries: int = 100_000,
        ttl_secs: int = 3600,
    ) -> None:
        self._path = Path(path)
        self._max = max_entries
        self._ttl = timedelta(seconds=ttl_secs)
        self._lock = threading.Lock()

    def _read(self) -> dict[str, datetime]:
        if not self._path.exists():
            return {}
        try:
            raw = json.loads(self._path.read_text() or "{}")
        except (json.JSONDecodeError, OSError):
            return {}
        out: dict[str, datetime] = {}
        for k, v in raw.items():
            try:
                out[k] = datetime.fromisoformat(v.replace("Z", "+00:00"))
            except (ValueError, TypeError, AttributeError):
                continue
        return out

    def _write(self, state: dict[str, datetime]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        raw = {k: v.isoformat() for k, v in state.items()}
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(raw))
        os.replace(tmp, self._path)

    def is_replay(self, nonce: str) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            state = self._read()
            cutoff = now - self._ttl
            state = {k: v for k, v in state.items() if v > cutoff}
            return nonce in state

    def record(self, nonce: str) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            state = self._read()
            cutoff = now - self._ttl
            state = {k: v for k, v in state.items() if v > cutoff}
            if len(state) >= self._max:
                oldest_key = min(state, key=state.get)  # type: ignore[arg-type]
                state.pop(oldest_key, None)
            state[nonce] = now
            try:
                self._write(state)
            except OSError:
                # Best-effort persistence; matches Rust FileNonceChecker.
                pass

    def check_and_record(self, nonce: str) -> bool:
        """Atomic check+record under the process-local lock. NOTE: this
        is process-local only — for cross-process atomicity use the
        Rust `FileNonceChecker` (which holds a `fs2` advisory file lock)
        or a Redis/SQL backend."""
        now = datetime.now(timezone.utc)
        with self._lock:
            state = self._read()
            cutoff = now - self._ttl
            state = {k: v for k, v in state.items() if v > cutoff}
            if nonce in state:
                return False
            if len(state) >= self._max:
                oldest_key = min(state, key=state.get)  # type: ignore[arg-type]
                state.pop(oldest_key, None)
            state[nonce] = now
            try:
                self._write(state)
            except OSError:
                pass
            return True


@dataclass
class VerifyOptions:
    """Options for verify_request()."""

    trusted_keys: list[str] = field(default_factory=list)
    """List of trusted 'ed25519:<base64>' pubkeys.
    If empty, trust any signer with a valid signature (skip trust check)."""

    trust_bundle: dict[str, Any] | None = None
    """Structured trust bundle. Active agent keys are treated as trust anchors."""

    require_signature: bool = True
    """Reject unsigned requests. Default: True."""

    max_age: int = 300
    """Max age of receipt in seconds. Default: 300 (5 min)."""

    expected_target: str | None = None
    """If set, receipt.action.target must match this value."""

    nonce_checker: NonceChecker | None = None
    """Optional replay-protection backend. When set, every verified
    request's `receipt.nonce` is checked against the backend; if seen
    before, the request is rejected with `replay detected`. Otherwise
    the nonce is recorded.

    Use FileNonceChecker (or a Redis/SQL implementation) for replay
    protection that survives process restarts. Without this hook, a
    restarted server has no replay defenses for previously-seen
    requests."""


@dataclass
class ServerVerifyResult:
    """Result of verify_request()."""

    ok: bool
    signer_name: str | None = None
    signer_pubkey: str | None = None
    error: str | None = None
    has_receipt: bool = False
    trusted: bool = False


def _active_agent_keys_from_bundle(bundle: dict[str, Any]) -> list[str]:
    if not isinstance(bundle, dict):
        raise ValueError("invalid trust bundle")

    agents = bundle.get("agents", [])
    if not isinstance(agents, list):
        raise ValueError("invalid trust bundle")

    now = datetime.now(timezone.utc)
    trusted_keys: list[str] = []

    for entry in agents:
        if not isinstance(entry, dict):
            raise ValueError("invalid trust bundle")
        if entry.get("status") != "active":
            continue

        pubkey = entry.get("pubkey")
        if not isinstance(pubkey, str):
            raise ValueError("invalid trust bundle")

        expires_at = entry.get("expires_at")
        if expires_at is not None:
            if not isinstance(expires_at, str):
                raise ValueError("invalid trust bundle")
            try:
                expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue
            if expiry < now:
                continue

        trusted_keys.append(pubkey)

    return trusted_keys


def verify_request(
    params: dict[str, Any],
    options: VerifyOptions | None = None,
) -> ServerVerifyResult:
    """Verify a Signet signature in an MCP tool call request.

    Args:
        params: The request params dict (should contain _meta._signet).
        options: Verification options (trusted keys, freshness, etc.).

    Returns:
        VerifyResult with ok=True if verified, ok=False with error if not.
    """
    opts = options or VerifyOptions()

    # 1. Extract _meta._signet
    meta = params.get("_meta")
    signet = meta.get("_signet") if isinstance(meta, dict) else None

    # 2. Check presence
    if signet is None:
        if opts.require_signature:
            return ServerVerifyResult(
                ok=False,
                error="unsigned request",
                has_receipt=False,
                trusted=False,
            )
        return ServerVerifyResult(ok=True, has_receipt=False, trusted=False)

    # 3. Validate receipt shape
    if not isinstance(signet, dict):
        return ServerVerifyResult(
            ok=False,
            error="malformed receipt",
            has_receipt=True,
            trusted=False,
        )
    for key in ("v", "sig", "action", "signer", "ts"):
        if key not in signet:
            return ServerVerifyResult(
                ok=False,
                error="malformed receipt",
                has_receipt=True,
                trusted=False,
            )

    # 4. Verify signature
    try:
        receipt = Receipt.from_json(json.dumps(signet))
    except Exception:
        return ServerVerifyResult(
            ok=False,
            error="malformed receipt",
            has_receipt=True,
            trusted=False,
        )

    prefixed_pubkey = receipt.signer.pubkey
    bare_pubkey = (
        prefixed_pubkey[len("ed25519:") :]
        if prefixed_pubkey.startswith("ed25519:")
        else prefixed_pubkey
    )

    try:
        valid = verify(receipt, bare_pubkey)
    except Exception:
        return ServerVerifyResult(
            ok=False,
            error="invalid signature",
            has_receipt=True,
            trusted=False,
        )

    if not valid:
        return ServerVerifyResult(
            ok=False,
            error="invalid signature",
            has_receipt=True,
            trusted=False,
        )

    # 5. Check trusted keys — empty trusted_keys and no trust_bundle means
    # "verify signature only, don't check trust". Supplying a trust bundle
    # enables anchored verification even if trusted_keys is empty.
    try:
        trust_bundle_keys = (
            _active_agent_keys_from_bundle(opts.trust_bundle)
            if opts.trust_bundle is not None
            else []
        )
    except ValueError:
        return ServerVerifyResult(
            ok=False,
            error="invalid trust bundle",
            has_receipt=True,
            trusted=False,
        )

    trusted_keys = list(dict.fromkeys([*opts.trusted_keys, *trust_bundle_keys]))
    trust_anchors_provided = bool(opts.trusted_keys) or opts.trust_bundle is not None

    if trust_anchors_provided:
        if prefixed_pubkey not in trusted_keys:
            return ServerVerifyResult(
                ok=False,
                error=f"untrusted signer: {prefixed_pubkey}",
                has_receipt=True,
                trusted=False,
            )

    # 6. Check freshness
    try:
        receipt_time = datetime.fromisoformat(receipt.ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return ServerVerifyResult(
            ok=False,
            error="invalid receipt timestamp",
            has_receipt=True,
            trusted=False,
        )

    now = datetime.now(timezone.utc)
    age = (now - receipt_time).total_seconds()

    if age > opts.max_age:
        return ServerVerifyResult(
            ok=False,
            error="receipt too old",
            has_receipt=True,
            trusted=False,
        )
    if age < -CLOCK_SKEW_TOLERANCE_SECONDS:
        return ServerVerifyResult(
            ok=False,
            error="receipt from future",
            has_receipt=True,
            trusted=False,
        )

    # 7. Check target
    if opts.expected_target and receipt.action.target != opts.expected_target:
        return ServerVerifyResult(
            ok=False,
            error=f"target mismatch: expected {opts.expected_target}, got {receipt.action.target}",
            has_receipt=True,
            trusted=False,
        )

    # 8. Anti-staple: tool name
    request_tool = params.get("name")
    if request_tool is not None and receipt.action.tool != request_tool:
        return ServerVerifyResult(
            ok=False,
            error=f'tool mismatch: receipt signed for "{receipt.action.tool}", request is for "{request_tool}"',
            has_receipt=True,
            trusted=False,
        )

    # 9. Anti-staple: params (use raw signet dict to avoid Rust type coercion)
    request_args = params.get("arguments")
    receipt_params = signet.get("action", {}).get("params")
    if request_args is not None or receipt_params is not None:
        signed = json.dumps(receipt_params, separators=(",", ":")) if receipt_params is not None else "null"
        actual = json.dumps(request_args, separators=(",", ":")) if request_args is not None else "null"
        if signed != actual:
            return ServerVerifyResult(
                ok=False,
                error="params mismatch: signed params differ from request arguments",
                has_receipt=True,
                trusted=False,
            )

    # 10. Replay protection (optional). Use the atomic check_and_record
    # primitive so two concurrent verifications of the same nonce cannot
    # both observe it as fresh. Fall back to is_replay → record for
    # legacy backends that don't implement check_and_record.
    if opts.nonce_checker is not None:
        nonce = receipt.nonce
        if not isinstance(nonce, str) or not nonce:
            return ServerVerifyResult(
                ok=False,
                error="missing nonce",
                has_receipt=True,
                trusted=False,
            )
        check_and_record = getattr(opts.nonce_checker, "check_and_record", None)
        if callable(check_and_record):
            if not check_and_record(nonce):
                return ServerVerifyResult(
                    ok=False,
                    error="replay detected",
                    has_receipt=True,
                    trusted=False,
                )
        else:
            # Legacy non-atomic path (warning: race-prone under concurrency).
            if opts.nonce_checker.is_replay(nonce):
                return ServerVerifyResult(
                    ok=False,
                    error="replay detected",
                    has_receipt=True,
                    trusted=False,
                )
            opts.nonce_checker.record(nonce)

    # All checks pass
    return ServerVerifyResult(
        ok=True,
        signer_name=receipt.signer.name,
        signer_pubkey=prefixed_pubkey,
        has_receipt=True,
        trusted=trust_anchors_provided,
    )
