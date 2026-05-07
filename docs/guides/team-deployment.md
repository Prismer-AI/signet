# Signet Pilot Deployment Runbook

This runbook is the supported path for a **founder-assisted pilot** of one
protected workflow. It assumes:

- one champion team
- one control owner
- one environment (dev → staging → prod is fine, but staged sequentially)
- TypeScript or CLI-centered execution boundary
- one MCP server or one internal tool path under Signet's protection

If you are evaluating Signet for general adoption, read [README.md](../../README.md)
first. If you are about to deploy, follow this document end-to-end.

---

## 0. Decide what you are protecting

Pick **one** workflow. Examples:

- An MCP gateway in front of GitHub, Slack, Jira, or one internal admin tool
- One deployment or remediation path
- One document-action or ticket-action flow with a clear server boundary

Bad fits for the first pilot:

- Broad multi-team rollout
- Workflows that require rich approval orchestration
- Customer self-service from day one
- Python-heavy server enforcement as the **only** boundary

---

## 1. Environment layout

Recommended on-host layout for a single pilot environment:

```text
/var/lib/signet/
├── keys/                        # Ed25519 keypairs (mode 0700)
│   ├── agent-pilot.key          # the agent's signing key
│   ├── agent-pilot.pub
│   ├── server-pilot.key         # the persistent proxy server key
│   └── server-pilot.pub
├── audit/                       # hash-chained audit log (rotated daily)
│   └── 2026-04-28.jsonl
├── nonces/
│   └── proxy-pilot.json         # FileNonceChecker state (proxy-side)
├── bundles/                     # evidence bundles for handoff
│   └── 2026-04-28T12-00-monthly/
└── trust/
    └── pilot.json               # trust bundle (active roots / agents / servers)
```

Set `SIGNET_HOME=/var/lib/signet`. Permissions: `0700` for `keys/`,
`0750` for everything else, owned by the service user (e.g. `signet`).

---

## 2. Generate identities

```bash
# Agent identity (the workload that initiates tool calls)
SIGNET_PASSPHRASE=$AGENT_PASS \
  signet identity generate --name agent-pilot

# Persistent server identity (the proxy / execution boundary)
SIGNET_PASSPHRASE=$SERVER_PASS \
  signet identity generate --name server-pilot
```

Why two identities:

- The agent's key proves "the workload requested this action."
- The proxy's `--server-key` proves "the execution boundary observed and
  responded." Bilateral co-signing requires **independent** identities;
  one key compromised cannot forge both sides.

Verify both keys exist:

```bash
signet identity list
```

---

## 3. Build a trust bundle

Sample `trust/pilot.json`:

```json
{
  "id": "tb_pilot",
  "version": 1,
  "environment": "pilot",
  "agents": [
    { "name": "agent-pilot", "pubkey": "ed25519:<paste-from-identity-list>", "added_at": "2026-04-28T12:00:00Z" }
  ],
  "servers": [
    { "name": "server-pilot", "pubkey": "ed25519:<paste-from-identity-list>", "added_at": "2026-04-28T12:00:00Z" }
  ],
  "active_root_pubkeys": []
}
```

Pin this file. **Verifiers anchor here.** Without a stable
`server-pilot` pubkey, trust bundles cannot validate v3 bilateral
receipts at all; this is why `--server-key` (Step 4) is mandatory.

---

## 4. Run the proxy with persistent server identity

```bash
signet proxy \
  --target "npx @modelcontextprotocol/server-github" \
  --key agent-pilot \
  --server-key server-pilot
```

What changes vs the demo path:

- `--server-key server-pilot` makes the **server pubkey stable across
  restarts**. Without it, the proxy generates an ephemeral key each run
  and trust bundles cannot anchor it.
- The proxy refuses to start if `--key` and `--server-key` resolve to
  the same identity.
- Startup line shows `(persistent: server-pilot)` instead of `(ephemeral)`.

If the proxy crashes or is restarted, the server pubkey **does not
change**. Existing receipts still verify. New receipts continue chaining
under the same server identity.

---

## 5. Verify with durable replay protection

Verifier-side, use a persistent nonce store so replay defenses survive
verifier restarts. The same primitive is exposed from all three
languages.

**CLI (`signet verify`):**

```bash
signet verify path/to/bilateral-receipt.json \
  --trust-bundle /var/lib/signet/trust/pilot.json \
  --nonce-store /var/lib/signet/nonces/verifier.json
```

**Python server (`signet_auth.verify_request`):**

```python
from signet_auth import verify_request, VerifyOptions, FileNonceChecker

opts = VerifyOptions(
    trust_bundle=..., trusted_keys=[...],
    nonce_checker=FileNonceChecker("/var/lib/signet/nonces/server.json"),
)
result = verify_request(params, opts)
# replay → result.ok == False, result.error == "replay detected"
```

**TypeScript server (`@signet-auth/mcp-server`):**

```ts
import { verifyRequest, FileNonceCache } from '@signet-auth/mcp-server';

const cache = new FileNonceCache('/var/lib/signet/nonces/mcp.json');
const result = verifyRequest(req, { trustBundle, nonceCache: cache });
// replay → result.ok === false, result.error contains 'nonce'
```

A second verification of the same receipt **fails with a replay error**
because the nonce file persists across process restarts.

When replaying historical receipts intentionally (incident analysis,
audit reconstruction) use a separate path or omit the persistent
backend to get only in-process replay protection. Document which mode
each verification job uses.

For multi-host or HA deployments, `FileNonceChecker` / `FileNonceCache`
are not enough — implement the same trait/interface against Redis or
your DB and supply that instead.

---

## 6. Capture outcomes (not just intent)

A v1 receipt proves the workload **intended** to call a tool. To
upgrade to a "signed workflow result", produce a v3 bilateral receipt
**with an outcome** at the execution boundary:

Python:

```python
import signet_auth as sa
# After the tool actually executed (or failed):
bilateral = sa.sign_bilateral_with_outcome(
    server_secret_key, agent_receipt, response_content, "server-pilot",
    outcome={"status": "executed"},  # or "failed" + error / "rejected" + reason
)
```

Status vocabulary:

| status | when to use | required field |
| --- | --- | --- |
| `requires_approval` | execution boundary paused waiting for approval | `reason` |
| `executed` | tool ran and returned a response | (none) |
| `failed` | execution started but errored | `error` |
| `rejected` | pre-execution check denied the action | `reason` |
| `verified` | signature/policy verified, not yet executed | (rare) |

The outcome lives **inside the signature scope** — tampering
invalidates the receipt.

Current proxy boundary note:

- `signet proxy` now records signed bilateral outcomes automatically for
  normal execution-boundary responses:
  - successful server response → `executed`
  - JSON-RPC / MCP error response → `failed`
- local proxy-side policy outcomes are also signed without forwarding
  upstream:
  - policy deny → `rejected`
  - policy `require_approval` → `requires_approval`
- the proxy still appends a hash-chained `policy_violation` audit record
  alongside those bilateral outcomes for easier operator review

---

## 7. Encrypted audit log (optional, recommended)

When `action.params` contains regulated content (PII, customer data),
turn on encrypted audit:

```bash
SIGNET_PASSPHRASE=$AUDIT_PASS \
  signet sign --key agent-pilot --tool ... --encrypt-params
```

Audit reviewers materialize params back via:

```bash
SIGNET_PASSPHRASE=$AUDIT_PASS \
  signet audit --export reviewed.json --decrypt-params
```

The hash chain integrity does **not** depend on having the passphrase —
verification still works on encrypted records. The passphrase is only
required to read the cleartext params.

---

## 8. Evidence export and restore

For audit handoff (monthly review, incident response, regulator request),
build a portable signed evidence bundle:

```bash
signet audit --since 30d \
  --bundle /var/lib/signet/bundles/2026-04-28T12-00-monthly \
  --include-trust-bundle /var/lib/signet/trust/pilot.json
```

Bundle contents:

```text
records.jsonl       # one audit record per line, deterministic JSON
manifest.json       # producer, host, count, chain start/tip, sha256, time range
hash-summary.txt    # human + machine readable summary
trust-bundle.json   # snapshot of the trust bundle at export time (optional)
```

Move the bundle off-host (S3, evidence repo, encrypted volume).

Re-verify on **any machine, no signet keystore required**:

```bash
signet audit --restore /path/to/bundle
```

Restore checks:

- `records.jsonl` SHA-256 matches manifest
- Each record's `prev_hash` chains to the prior record
- Final `record_hash` matches the manifest's chain tip
- Record count matches manifest

A failure here is reportable evidence of post-export tampering.

---

## 9. Operating procedures

### Daily

- `signet explore --since 24h` — quick visual sanity check
- `signet audit --since 24h --verify` — re-verify all signatures
- `signet verify --chain` — confirm the hash chain is unbroken

### Weekly

- Build a fresh evidence bundle, archive off-host
- Rotate `nonces/*.json` (keep last 7 days)
- Review any `failed` or `rejected` outcomes

### Monthly

- Bundle for compliance handoff
- Review trust bundle (`agents[]`, `servers[]`) — disable any retired
  identity by setting `disabled_at`
- Re-confirm `server-pilot` pubkey across operators

### On compromise / incident

1. **Disable** the affected identity in the trust bundle (`disabled_at`).
   Existing bundles produced before that timestamp remain verifiable.
2. **Rotate** the affected key (`signet identity generate --name <new>`).
   Add it to the trust bundle.
3. **Restart** the proxy with the new `--key` or `--server-key`.
4. **Bundle** the audit log up to and including the incident window;
   move off-host as forensic evidence.
5. **Verify** post-incident with `signet audit --restore` on a second
   host to confirm the bundle is intact.

---

## 10. Operator-facing FAQ

**Can I verify offline?** Yes. Bundles include everything needed for
verification. The verifier needs only the bundle directory and (for v4
authorized receipts) the trusted root pubkey.

**Does the proxy need internet?** No. Signing happens client-side.
Downstream MCP servers may need internet for their own work.

**What if the audit log is deleted?** The hash chain is local, so a
filesystem-level wipe destroys it. Mitigations: encrypted audit
storage, periodic bundle export to off-host storage, append-only file
systems for the audit directory.

**Do I need an HSM?** Not for the first pilot. Argon2id-encrypted
keystore on `0700` directories is sufficient for the supported wedge.
HSM/KMS support is on the roadmap for broader rollouts.

**What about Windows / Homebrew / signed binaries?** Not part of the
supported pilot path today. Use Linux or macOS hosts with the
crates.io / npm / PyPI installs.

---

## 11. What this runbook does NOT cover

- Self-serve customer-operated installation without founder narration
  (active gap; comes after wider stabilization)
- Multi-tenant admin UI or hosted control plane
- Trusted timestamping / RFC 3161
- HSM / cloud KMS integration
- Multi-host or HA replay protection (`FileNonceChecker` is single-host)
- Windows support
- Binary signing & notarization

These are tracked in the project roadmap. If you need them for the pilot,
flag it before kickoff so we can find a workaround.
