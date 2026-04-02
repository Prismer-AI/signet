# Audit Log Guide

Signet maintains an append-only, hash-chained audit log of all signed actions.

## Storage Location

```
~/.signet/audit/
├── 2026-03-29.jsonl
├── 2026-03-30.jsonl
└── 2026-03-31.jsonl
```

Override with `SIGNET_HOME` environment variable:

```bash
export SIGNET_HOME=/var/lib/signet
# Audit log: /var/lib/signet/audit/
# Keys: /var/lib/signet/keys/
```

## Log Format

Each `.jsonl` file contains one `AuditRecord` per line:

```json
{
  "receipt": { "v": 1, "id": "rec_...", "action": {...}, "signer": {...}, "ts": "...", "nonce": "...", "sig": "..." },
  "prev_hash": "sha256:abc123...",
  "record_hash": "sha256:def456..."
}
```

## Querying

### Recent actions

```bash
# Last 24 hours
signet audit --since 24h

# Last 7 days
signet audit --since 7d
```

### Filter by tool

```bash
# All GitHub-related actions
signet audit --tool github

# Exact tool name works too
signet audit --tool github_create_issue
```

### Filter by signer

```bash
signet audit --signer my-agent
```

### Combine filters

```bash
signet audit --since 7d --tool deploy --signer ci-bot --limit 20
```

### Export as JSON

```bash
signet audit --export report.json
signet audit --since 24h --export today.json
```

## Verifying Integrity

### Verify the hash chain

```bash
signet verify --chain
```

This walks every record chronologically and checks:
1. Each `prev_hash` matches the previous record's `record_hash`
2. Each `record_hash` is correctly computed from `{prev_hash, receipt}`

If any record was modified, deleted, or reordered, the chain breaks.

### Verify all signatures

```bash
signet audit --verify
```

This verifies the Ed25519 signature on every receipt in the log.

### Combined check

```bash
# Verify both chain integrity and all signatures
signet verify --chain && signet audit --verify
```

## Hash Chain Explained

```
Record 1                    Record 2                    Record 3
┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
│ receipt: {...}   │        │ receipt: {...}   │        │ receipt: {...}   │
│ prev_hash:       │        │ prev_hash:       │        │ prev_hash:       │
│   sha256:0000... │──┐     │   sha256:aaa1... │──┐     │   sha256:bbb2... │
│ record_hash:     │  │     │ record_hash:     │  │     │ record_hash:     │
│   sha256:aaa1... │──┘─────│   sha256:bbb2... │──┘─────│   sha256:ccc3... │
└─────────────────┘        └─────────────────┘        └─────────────────┘
      genesis                  links back                  links back
```

- **Genesis**: First record uses `sha256:0000...0000` as `prev_hash`
- **Cross-day**: Files are split by date, but the chain continues across files
- **Tamper-evident**: Modifying any record invalidates all subsequent hashes

## Python API

```python
from signet_auth import SigningAgent

agent = SigningAgent.create("my-agent", owner="willamhou")

# Sign (auto-appends to audit log)
receipt = agent.sign("github_create_issue", params={"title": "fix bug"})

# Query
for record in agent.audit_query(since="24h"):
    print(f"{record.receipt.ts} {record.receipt.action.tool}")

for record in agent.audit_query(tool="github", limit=10):
    print(f"{record.receipt.signer.name}: {record.receipt.action.tool}")
```

## Tips

- **Backup**: Regularly back up `~/.signet/audit/` — once deleted, the chain is gone
- **Rotation**: Keys can be rotated without affecting the audit log; old receipts remain verifiable with old public keys
- **Disk usage**: Each record is ~500 bytes. 10,000 tool calls/day = ~5MB/day
- **Skip logging**: Use `signet sign --no-log` for actions you don't need to audit (e.g., dry runs)
