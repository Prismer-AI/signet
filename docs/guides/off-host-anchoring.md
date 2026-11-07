# Off-host anchoring (draft)

> Status: draft for review (issue #13). Optional and off by default.
> Disclosure: the one sink in this draft, DEUSPROOF, is operated by the author of this change.

The audit log is a local hash chain. It detects edits, but someone with write access to the host can
delete it, truncate it, or restore an older copy and the remaining chain still verifies. Anchoring
fixes the state of the chain (its tip hash and record count) in an external timestamping service. An
auditor who keeps one of those anchors can later tell whether the log they are shown still extends
it.

Nothing in signing, `signet audit` (without the new flags), `audit::append` or local verification uses
this, the network, or any account.

## Quick start

```bash
# Network support (the sink and Bitcoin Core RPC) is a cargo feature.
cargo install --path signet-cli --features anchoring

signet audit --anchor deusproof              # submit a commitment to the current tip
signet audit --refresh-anchors deusproof     # later: fetch the upgraded Bitcoin proof
signet audit --export-checkpoint anchor.json # hand this to whoever audits you
# or both at once: signet audit --anchor deusproof --export-checkpoint anchor.json

# The auditor, on their own machine, with their own Bitcoin node:
signet audit --verify-anchors \
  --bitcoin-rpc http://127.0.0.1:8332 --bitcoin-rpc-cookie ~/.bitcoin/.cookie \
  --checkpoint anchor.json
```

`--verify-anchors` exits 0 only when the result is `verified`.

## Two things that are kept apart

**Proof verification** is offline. `verify_anchors` recomputes every commitment from the local log,
validates the exact sealed bytes, and checks the stored proofs itself. It never calls the sink and
never reads a stored status (there is none to read).

**Checkpoint discovery and retention** is not solved by this change. A proof shows that a chain
state existed by some time. It cannot show that an anchor is the *latest* one: looking up a known
commitment `C` at the sink only confirms that `C` exists. If a host deletes or rolls back the log
**and** its anchors together, only a checkpoint retained outside the host reveals it. That is what
`--checkpoint` is for. Without one, the report says so on every run:

```
- no auditor checkpoint given: deletion or rollback of the log together with its anchors cannot be ruled out
```

Records written after the latest verified anchor are not protected by any anchor; the report prints
how many there are, and `--max-unanchored N` turns more than `N` into `missing`.

## What an anchor commits to

```
C = sha256( JCS({"count": <records since genesis>,
                 "kind": "signet-audit-anchor",
                 "prev_anchor": <C of the previous anchor, or null>,
                 "tip": <record_hash of record number count>,
                 "v": 1}) )
```

`count` and `tip` together bind the length and the content of the chain, so truncation, replacement
and reordering all change `C`. `prev_anchor` chains the anchors. A test pins the exact preimage
bytes (`commitment_preimage_is_pinned`).

## Sealed bytes

External proofs never cover `C` directly. They cover `sha256(sealed_bytes)`, and `sealed_bytes` has
one exact layout per format. The verifier parses the whole structure; containing `C` somewhere is not
enough.

| `sealed_format` | `sealed_bytes` |
|---|---|
| `raw-sha256-v1` | the 32 bytes of `C` |
| `deusproof-seed-v1` | ASCII `":" + lowerhex(C) + ":" + record_id`, 102 bytes, where `record_id` is the sink's lowercase hyphenated UUID and must equal `sink_ref` |

`deusproof-seed-v1` is the string DEUSPROOF timestamps for a hash-only record
(`prompt_hash:output_hash:id` with an empty `prompt_hash`); it is served at
`/api/anchors/seed/<id>` once a proof exists, and the sink checks it byte for byte.

## Anchor records

`<signet dir>/anchors/anchors.jsonl`, outside `<signet dir>/audit`, so the audit reader (which reads
every `.jsonl` in its directory) is unaffected. One JSON object per line; unknown fields are rejected.

```json
{"v":1,"commitment":"sha256:…","count":12,"tip":"sha256:…","prev_anchor":"sha256:…"|null,
 "sink":"deusproof","sink_ref":"<uuid>","sealed_format":"deusproof-seed-v1",
 "sealed_bytes_b64":"…","submitted_at":"2026-11-05T15:00:00Z",
 "proofs":[{"kind":"opentimestamps","data_b64":"…"},{"kind":"rfc3161","data_b64":"…"}]}
```

`submitted_at` is informational. `--refresh-anchors` only ever changes `proofs`, and never trades
existing evidence for an unverified candidate:

- an OpenTimestamps proof that already carries a Bitcoin attestation is kept. It is replaced only when
  `--bitcoin-rpc` is given, the stored proof fails against your node, and the candidate verifies;
- a pending proof is upgraded by a candidate that parses and covers the same bytes. With
  `--bitcoin-rpc`, a candidate's Bitcoin attestation must also verify;
- rejected candidates and sink failures are listed, partial updates are kept, and the command exits
  non-zero if anything failed.

`--export-checkpoint FILE` can be combined with `--anchor` or `--refresh-anchors`: the file is written
after that operation succeeds, and the command fails if it cannot be written. It cannot be combined with
`--verify-anchors`.

## Results

Per anchor:

| status | meaning |
|---|---|
| `verified` | structure checks pass and a Bitcoin attestation matched a header from your node |
| `pending` | structure checks pass; the OpenTimestamps proof is not upgraded yet |
| `unavailable` | structure checks pass; the proof is missing, or no node was given, or the node could not answer |
| `invalid` | something does not match: the log, the commitment, the sealed bytes, or the proof |

Overall verdict: `invalid` if any anchor or the auditor checkpoint fails; `missing` if there are no
anchors (or too many unanchored records); otherwise the status of the latest anchor. Only `verified`
is success.

Checkpoint outcomes: `consistent`, `log_truncated` (the log is shorter than the checkpoint),
`log_diverged` (the anchored record was replaced), `anchors_rolled_back` (the host shows only older
anchors), `anchors_forked` (the anchor history no longer contains the checkpoint), `invalid`.

## Trust assumptions

- **Bitcoin.** The only mode in this draft reads block headers from **your own validating Bitcoin
  Core node** (`getblockhash`, then `getblockheader`, requiring at least one confirmation). Matching
  two or more independent block explorers is a different, weaker trust assumption; it is not
  implemented here and would be documented as its own mode.
- **RFC 3161.** The sink's timestamp token is stored but **not checked** by this draft. Checking it
  needs a pinned TSA certificate chain; that is follow-up work, and until then the token never
  contributes to `verified`.
- **What `verified` proves.** That this exact chain state (`count` records ending in `tip`) existed no
  later than the time of the Bitcoin block. It says nothing about whether the recorded actions were
  right, and nothing about records written after the anchor.
- **The sink is not trusted for verification.** A sink can refuse service or lose records; it cannot
  make a wrong chain verify, because every check is recomputed locally against Bitcoin.

## Names, authentication and correlation

By default the sink receives **only the 32-byte commitment** (plus `platform: "signet"` and the
client's User-Agent). No name is sent. At DEUSPROOF such records sit in a shared, unnamed drawer
that no key can ever claim, and they share one hourly submission budget (60 per hour today); a
named handle has its own. Resubmitting the same commitment returns the same record.

`--anchor-handle NAME` is an explicit opt-in to identity-linked discovery: anchors are filed under a
public name and anyone can list them (`GET /api/agents/NAME/profile`), which lets an auditor find
the latest public anchor without asking the host.

- **Submissions are not authenticated as the signer's.** DEUSPROOF accepts a hash filed under a
  name without any signature from that name's key. A listing by name is therefore a discovery aid, never evidence
  of who filed it. The verifier does not use names at all: an anchor counts only if it matches the
  local chain and its proof checks out. (DEUSPROOF can bind a name to an Ed25519 key through a
  challenge–response claim; wiring the Signet signer key into that is possible follow-up work and is
  not part of this draft.)
- **Correlation.** A commitment reveals nothing about the log's content, but a public name makes the
  *times and frequency* of anchoring linkable to that name, which can expose an agent's activity
  pattern. Even without a name, the sink sees the submitting IP address.

## Not in this draft

RFC 3161 verification with a pinned TSA chain; a discovery source; the two-source Bitcoin mode;
other sinks (`raw-sha256-v1` is there for a sink that timestamps `C` itself, e.g. an
OpenTimestamps calendar); scheduled anchoring.
