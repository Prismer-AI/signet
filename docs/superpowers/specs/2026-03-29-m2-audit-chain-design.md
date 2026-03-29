# M2: Audit Log + Hash Chain — Design Spec

**Date:** 2026-03-29
**Status:** Draft
**Depends on:** M1 (complete — signet-core identity/sign/verify + signet-cli)

## Goal

Add an append-only JSONL audit log with SHA-256 hash chain to signet-core, and
extend the CLI with audit query, signature verification, chain integrity checking,
and export commands.

## Non-Goals

- MCP transport integration (M3)
- Off-host chain anchoring (v2+)
- Audit log encryption (v2+)
- Real-time log streaming / tail -f (v2+)
- Database backend (always JSONL files)

## Exit Criteria

1. `signet sign` automatically appends receipt to audit log after signing
2. `signet sign --no-log` skips audit log append
3. `signet audit` lists recent actions in table format
4. `signet audit --since 24h` filters by time
5. `signet audit --tool github` filters by tool name substring
6. `signet audit --verify` verifies all receipt signatures
7. `signet audit --export report.json` exports audit records as JSON array
8. `signet verify --chain` validates hash chain integrity across all log files
9. Hash chain is continuous across day-boundary files
10. `cargo test --workspace` passes with all new + existing tests
11. WASM binding still compiles and passes

## Architecture

```
┌──────────────────────────────────────────┐
│              signet-cli                    │
│                                           │
│  cmd_sign.rs    — sign → audit::append()  │
│  cmd_audit.rs   — audit query/verify/export│
│  cmd_verify.rs  — verify + --chain        │
└───────────────────┬──────────────────────┘
                    │ calls
                    v
┌──────────────────────────────────────────┐
│              signet-core                  │
│                                           │
│  audit.rs  (#[cfg(not(target_arch = "wasm32"))]) │
│    append(dir, receipt) → AuditRecord     │
│    query(dir, filter) → Vec<AuditRecord>  │
│    verify_chain(dir) → ChainStatus        │
│    verify_signatures(dir, filter) → VerifyResult │
└──────────────────────────────────────────┘
```

## Audit Record Format

Each line in the JSONL file is a complete audit record:

```json
{"receipt":{"v":1,"id":"rec_...","action":{"tool":"github_create_issue","params":{"title":"bug"},"params_hash":"sha256:...","target":"mcp://github.local","transport":"stdio"},"signer":{"pubkey":"ed25519:...","name":"deploy-bot","owner":"willamhou"},"ts":"2026-03-29T14:32:00.123Z","nonce":"rnd_...","sig":"ed25519:..."},"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","record_hash":"sha256:abc123..."}
```

### Record Hash Computation

```
record_hash = sha256(JCS({"prev_hash": prev_hash, "receipt": receipt}))
```

The hash input is a deterministic canonical JSON object containing both the
receipt and the previous hash. This avoids string concatenation ambiguity and
reuses the same JCS logic as receipt signing.

### Chain Rules

- First record ever: `prev_hash` = `"sha256:"` + 64 zeros (sentinel value, not the hash of any input)
- Subsequent records: `prev_hash` = previous record's `record_hash`
- Chain is continuous across day-boundary files

### Rust Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub receipt: Receipt,
    pub prev_hash: String,
    pub record_hash: String,
}

pub struct AuditFilter {
    pub since: Option<DateTime<Utc>>,
    pub tool: Option<String>,    // substring match
    pub signer: Option<String>,  // exact match on signer.name
    pub limit: Option<usize>,
}

pub struct ChainStatus {
    pub total_records: usize,
    pub valid: bool,
    pub break_point: Option<ChainBreak>,
}

pub struct ChainBreak {
    pub file: String,
    pub line: usize,
    pub expected_hash: String,
    pub actual_hash: String,
}

pub struct VerifyResult {
    pub total: usize,
    pub valid: usize,
    pub failures: Vec<VerifyFailure>,
}

pub struct VerifyFailure {
    pub file: String,
    pub line: usize,
    pub receipt_id: String,
    pub reason: String,
}
```

## File Layout

```
~/.signet/                   # or $SIGNET_HOME
├── keys/                    # M1
└── audit/
    ├── 2026-03-29.jsonl     # one receipt per line, compact JSON
    └── 2026-03-30.jsonl     # auto-created on first write of the day
```

File naming: `YYYY-MM-DD.jsonl` based on UTC date of the receipt timestamp.

Records within a JSONL file are always in append/chronological order.
The query early-exit optimization depends on this invariant.

`--verify` and `--export` are mutually exclusive. If both are provided → error.
`--verify` can be combined with `--since`/`--tool`/`--signer` to verify a subset.

Read strategy: read all lines into `Vec<String>`, iterate in reverse for query.
Files are expected to be small enough (≤10K records/day) that full reads are OK.

The existing `canonical::canonicalize` is reused for record_hash computation.
No new JCS implementation required.

Note on `append` atomicity: `OpenOptions::append()` is atomic for writes < PIPE_BUF
(4096 bytes on Linux). If a receipt exceeds this (large params), the write may not be
atomic. Multi-process safety requires `flock` (v2+). For M2 single-process CLI, this
is acceptable.

## Core API: audit.rs

`#[cfg(not(target_arch = "wasm32"))]`

### append(dir, receipt) → Result<AuditRecord>

1. Determine target filename from `receipt.ts` (parse date portion) → `YYYY-MM-DD.jsonl`
   (Use receipt timestamp, NOT `Utc::now()`, to avoid midnight boundary bugs)
2. Create `~/.signet/audit/` directory if it doesn't exist
3. Find `prev_hash`:
   a. Read last line of today's file → extract `record_hash`
   b. If today's file is empty/missing → scan backwards for most recent .jsonl file,
      read its last line → extract `record_hash`
   c. If no history at all → use genesis hash (all zeros)
4. Compute `record_hash = sha256(JCS({"prev_hash": prev_hash, "receipt": receipt}))`
5. Build `AuditRecord { receipt, prev_hash, record_hash }`
6. Serialize as compact JSON (no newlines within the record)
7. Append line to today's file (open with `OpenOptions::append`)
8. Return the `AuditRecord`

**File locking:** Use `OpenOptions::append()` which is atomic at the OS level for
single-line writes. No explicit locking needed for single-process CLI usage.
Multi-process safety (v2+) would need `flock`.

### query(dir, filter) → Result<Vec<AuditRecord>>

1. List all .jsonl files in audit dir, sorted by date descending (newest first)
2. For each file, read lines in reverse order (newest first)
3. For each line, deserialize `AuditRecord`
4. Apply filters:
   - `since`: skip records where `receipt.ts < since` → stop scanning this and older files
   - `tool`: skip if `receipt.action.tool` does not contain the substring
   - `signer`: skip if `receipt.signer.name != signer`
5. Collect up to `limit` records (default: no limit)
6. Return in chronological order (reverse the collected results)

### verify_chain(dir) → Result<ChainStatus>

1. List all .jsonl files in audit dir, sorted by date ascending (oldest first)
2. Track `expected_prev_hash`, starting with genesis (all zeros)
3. For each record in each file:
   a. Check `record.prev_hash == expected_prev_hash`
   b. Recompute: `sha256(JCS({"prev_hash": record.prev_hash, "receipt": record.receipt}))`
   c. Check recomputed hash == `record.record_hash`
   d. Set `expected_prev_hash = record.record_hash`
4. If any check fails → return `ChainStatus { valid: false, break_point: Some(...) }`
5. If all pass → return `ChainStatus { valid: true, total_records: N, ... }`

### verify_signatures(dir, filter) → Result<VerifyResult>

1. Query records using filter (or all records if no filter)
2. For each record, extract `signer.pubkey` from receipt
3. Decode pubkey → `VerifyingKey`
4. Call `signet_core::verify(&receipt, &pubkey)`
5. Collect failures
6. Return `VerifyResult { total, valid, failures }`

Note: signature verification uses the pubkey embedded in the receipt, not the
local keystore. This means you can verify receipts from any agent, not just
your own.

## CLI Commands

### Modified: `signet sign`

After generating receipt, automatically append to audit log:

```
signet sign --key <name> --tool <tool> --params <json|@file> --target <uri>
            [--hash-only] [--output <file>] [--no-log]
```

`--no-log` skips audit log append. Default behavior: always log.

### New: `signet audit`

```
signet audit [--since <duration>] [--tool <substring>] [--signer <name>]
             [--limit <n>] [--verify] [--export <file>]
```

**Default output (table):**
```
TIME                          SIGNER       TOOL                     TARGET
2026-03-29T14:32:00.123Z      deploy-bot   github_create_issue      mcp://github.local
2026-03-29T14:33:01.456Z      deploy-bot   slack_send_message       mcp://slack.local
```

**--verify output:**
```
Verifying 42 receipts...
✅ 42/42 signatures valid
```

Or on failure:
```
Verifying 42 receipts...
❌ Record #17 (2026-03-29.jsonl:17): signature invalid
✅ 41/42 signatures valid, 1 FAILED
```
Exit code 0 if all valid, 1 if any failures.

**--export output:**
Writes a JSON array of `AuditRecord` objects to the specified file.
Applies the same filters (--since, --tool, --signer).

### Modified: `signet verify`

`VerifyArgs` refactor: both `receipt` and `pubkey` become `Option<String>`,
add `#[arg(long)] chain: bool`. Runtime validation:
- `--chain` present → run chain verification (receipt/pubkey must be absent)
- `receipt` + `--pubkey` present → run receipt verification (--chain must be absent)
- Otherwise → error with usage hint

```
signet verify <receipt.json> --pubkey <name-or-file>    # existing
signet verify --chain                                    # new: chain integrity check
```

**--chain output:**
```
Verifying chain integrity...
Scanning 3 files, 142 records...
✅ Chain intact: 142 records verified
```

Or on break:
```
Verifying chain integrity...
❌ Chain broken at 2026-03-29.jsonl:17
   expected prev_hash: sha256:abc123...
   actual prev_hash:   sha256:def456...
16 records OK before break
```
Exit code 0 if intact, 1 if broken.

### `--since` Duration Parsing

Simple hand-written parser, no external crate:
- `24h` → 24 hours ago
- `7d` → 7 days ago
- `30d` → 30 days ago
- `1h` → 1 hour ago

Regex: `^(\d+)(h|d)$`. Anything else → error with usage hint.

## File Map (new/modified)

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/signet-core/src/audit.rs` | Create | Audit log append/query/verify (#[cfg(not(wasm32))]) |
| `crates/signet-core/src/lib.rs` | Modify | Add `pub mod audit`, update re-exports |
| `signet-cli/src/cmd_audit.rs` | Create | audit subcommand (query/verify/export) |
| `signet-cli/src/cmd_sign.rs` | Modify | Add audit::append() after signing |
| `signet-cli/src/cmd_verify.rs` | Modify | Add --chain flag |
| `signet-cli/src/main.rs` | Modify | Add Audit subcommand to clap |

## Error Types

One new error variant needed:

```rust
#[cfg(not(target_arch = "wasm32"))]
#[error("corrupted audit record: {0}")]
CorruptedRecord(String),  // distinct from CorruptedFile (key-specific)
```

Existing variants also used:
- `IoError` for file operations
- `SerializeError` for JSON issues
- `SignatureMismatch` for signature verification failures

## Test Plan

### signet-core: audit tests (10 new)

| Test | What it validates |
|------|-------------------|
| `test_append_creates_file` | First append creates audit dir + JSONL file |
| `test_append_genesis_hash` | First record has all-zero prev_hash |
| `test_append_chain_continuity` | Second record's prev_hash == first's record_hash |
| `test_append_cross_day` | Pre-write yesterday's file, append today → chain links across files |
| `test_query_no_filter` | Returns all records |
| `test_query_since` | --since filters correctly |
| `test_query_tool_substring` | --tool "github" matches "github_create_issue" |
| `test_verify_chain_intact` | Valid chain → ChainStatus { valid: true } |
| `test_verify_chain_broken` | Tampered record → ChainStatus { valid: false, break_point } |
| `test_verify_signatures` | All valid → VerifyResult { failures: [] } |

### signet-cli: audit integration tests (6 new)

| Test | What it validates |
|------|-------------------|
| `test_sign_creates_audit_log` | sign → audit file exists with 1 record |
| `test_sign_no_log` | sign --no-log → no audit file |
| `test_audit_list` | sign 3 times → audit shows 3 records |
| `test_audit_since` | sign, wait, sign → --since 1h shows both |
| `test_audit_verify` | sign 3 → audit --verify → "3/3 valid" |
| `test_verify_chain` | sign 3 → verify --chain → "Chain intact" |

### Coverage

```
Module              Existing    M2 New    Total
──────────────────────────────────────────────
signet-core         34          10        44
signet-cli          14          6         20
──────────────────────────────────────────────
Total               48          16        64
```

## Success Definition

M2 is complete when:
1. All 11 exit criteria pass
2. `cargo test --workspace` passes (48 existing + 16 new = 64 tests)
3. No `unsafe` code
4. `cargo clippy --workspace` has no warnings
5. WASM binding still compiles and Node.js tests pass
6. Hash chain verified end-to-end: sign 10 actions → verify --chain → intact
