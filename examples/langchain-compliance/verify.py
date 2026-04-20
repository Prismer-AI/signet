"""Offline verification of the audit chain produced by agent.py.

Uses the signet_auth Python API (audit_verify_chain, audit_verify_signatures,
audit_query) to check the local audit log. A truly standalone Ed25519 + JCS
verifier (no signet_auth dependency) is a separate, future example.

Run after agent.py has produced at least one receipt:

    python verify.py
"""

from __future__ import annotations

from signet_auth import (
    SigningAgent,
    audit_query,
    audit_verify_chain,
    audit_verify_signatures,
    default_signet_dir,
    load_verifying_key,
)


def main() -> None:
    signet_dir = default_signet_dir()

    # 1. Hash chain integrity — detects any insertion, deletion, or reorder.
    chain = audit_verify_chain(signet_dir)
    print("=== Hash chain integrity ===")
    print(f"  total_records: {chain.total_records}")
    print(f"  valid: {chain.valid}")
    if chain.break_point:
        print(f"  break at: {chain.break_point}")

    # 2. Signature verification — confirms each record was signed by its claimed key.
    sigs = audit_verify_signatures(signet_dir)
    print("\n=== Signature verification ===")
    print(f"  total: {sigs.total}   valid: {sigs.valid}   failures: {len(sigs.failures)}")

    # 3. Show what the agent did.
    records = audit_query(signet_dir, signer="demo-bot", limit=20)
    print(f"\n=== Last {len(records)} actions by demo-bot ===")
    for record in records:
        receipt = record.receipt
        print(f"  {receipt.ts}  {receipt.action.tool:<20}  {receipt.id}")

    # 4. Independent verification with just the public key.
    # This is what an external auditor does: they have the audit log and the
    # public key file only — never the private key. `load_verifying_key` reads
    # `<signet_dir>/keys/<name>.pub.json` which is the non-secret half.
    if records:
        try:
            pubkey = load_verifying_key(signet_dir, "demo-bot")
            print("\n=== Independent per-receipt verification (public key only) ===")
            print(f"  public_key: ed25519:{pubkey[:24]}...")
            latest = records[0].receipt
            ok = SigningAgent.verify_with_key(latest, pubkey)
            print(f"  verify receipt {latest.id}: {ok}")
        except Exception as exc:  # noqa: BLE001 — demo script, surface the error
            print(f"\n  could not load demo-bot public key: {exc}")
            print("  (generate it with: signet identity generate --name demo-bot --unencrypted)")


if __name__ == "__main__":
    main()
