//! Optional off-host anchoring of the audit chain.
//!
//! An anchor fixes the state of the local audit chain (its tip `record_hash`
//! and record count) in an external timestamping service, so that a later
//! truncation, replacement or rollback of the log can be detected by someone
//! who does not have to trust the host.
//!
//! Two things are kept separate on purpose:
//!
//! * **Proof verification** ([`verify_anchors`]) is offline. It recomputes
//!   every commitment from the local chain, checks the exact sealed bytes, and
//!   checks the stored proofs itself. It never trusts a stored status and never
//!   calls the sink.
//! * **Checkpoint discovery and retention** is not solved here. Proofs show
//!   that a given chain state existed by some time; they cannot show that an
//!   anchor is the *latest* one. Detecting deletion or rollback of the log and
//!   its anchors together needs a checkpoint retained outside the host (see
//!   [`AnchorVerifyOptions::checkpoint`]) or a discovery source, which this
//!   module does not provide.
//!
//! Nothing in signing, `audit::append` or local verification depends on this
//! module, on the network or on any account. See `docs/guides/off-host-anchoring.md`.
#![cfg(not(target_arch = "wasm32"))]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{self, ChainStatus};
use crate::canonical;
use crate::error::SignetError;
use crate::ots;

/// Version of the on-disk [`AnchorRecord`] line.
pub const ANCHOR_RECORD_VERSION: u8 = 1;
/// Version of the commitment preimage.
pub const COMMITMENT_VERSION: u8 = 1;
pub const COMMITMENT_KIND: &str = "signet-audit-anchor";

/// `sealed_bytes` is the 32-byte commitment itself.
pub const SEALED_RAW_SHA256_V1: &str = "raw-sha256-v1";
/// `sealed_bytes` is the ASCII string `":" + lowerhex(C) + ":" + record_id`,
/// where `record_id` is the sink's lowercase hyphenated UUID for the record.
pub const SEALED_DEUSPROOF_SEED_V1: &str = "deusproof-seed-v1";

pub const PROOF_OPENTIMESTAMPS: &str = "opentimestamps";
pub const PROOF_RFC3161: &str = "rfc3161";

const ANCHORS_FILE: &str = "anchors.jsonl";

/// One line of `<signet dir>/anchors/anchors.jsonl`.
///
/// Every field except `submitted_at` and `proofs` is re-derived or re-checked
/// by the verifier. There is deliberately no `state` field: the verifier
/// derives the state from the proofs every time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorRecord {
    pub v: u8,
    /// `sha256:<hex>` of the commitment preimage (see [`compute_commitment`]).
    pub commitment: String,
    /// Number of audit records covered, counted from genesis.
    pub count: u64,
    /// `record_hash` of record number `count`.
    pub tip: String,
    /// Commitment of the previous anchor in this file, `None` for the first.
    pub prev_anchor: Option<String>,
    /// Identifier of the sink that received the commitment.
    pub sink: String,
    /// The sink's identifier for the submission.
    pub sink_ref: String,
    /// How `sealed_bytes_b64` is laid out (one of the `SEALED_*` constants).
    pub sealed_format: String,
    /// The exact bytes the external proofs commit to, via `sha256(sealed_bytes)`.
    pub sealed_bytes_b64: String,
    /// RFC 3339 time of submission, as reported by the host. Informational only.
    pub submitted_at: String,
    pub proofs: Vec<AnchorProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorProof {
    /// [`PROOF_OPENTIMESTAMPS`] or [`PROOF_RFC3161`].
    pub kind: String,
    pub data_b64: String,
}

/// What a sink hands back for a submitted commitment.
#[derive(Debug, Clone)]
pub struct SinkSubmission {
    pub sink_ref: String,
    pub sealed_format: String,
    pub sealed_bytes: Vec<u8>,
    /// Proofs available at submission time; often none yet.
    pub proofs: Vec<AnchorProof>,
}

/// A provider-neutral destination for commitments.
///
/// Implementations must not touch the local audit log. A sink error leaves
/// both the audit log and the anchors file unchanged.
pub trait AnchorSink {
    /// Stable identifier written into each anchor record.
    fn id(&self) -> &str;
    /// Submit a 32-byte commitment.
    fn submit(&self, commitment: &[u8; 32]) -> Result<SinkSubmission, String>;
    /// Fetch the current proofs for an earlier submission (e.g. an upgraded
    /// OpenTimestamps proof).
    fn refresh(&self, record: &AnchorRecord) -> Result<Vec<AnchorProof>, String>;
}

/// A Bitcoin block header, from a source the verifier trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    /// Merkle root in internal byte order (the reverse of RPC hex display).
    pub merkle_root: [u8; 32],
    pub time: u64,
}

/// Where the verifier gets Bitcoin block headers.
///
/// The only mode this module documents as verification is the auditor's own
/// validating node. Other modes (e.g. several independent explorers) are a
/// different trust assumption and are not implemented here.
pub trait BitcoinHeaderSource {
    /// Header of the block at `height` on the source's best chain.
    fn header_at(&self, height: u64) -> Result<BlockHeader, String>;
}

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("audit chain is broken: {0}")]
    ChainBroken(String),
    #[error("audit log is empty: nothing to anchor")]
    EmptyLog,
    #[error("the current tip is already anchored (record {0})")]
    AlreadyAnchored(u64),
    #[error("refusing to anchor: {0}")]
    Refused(String),
    #[error("anchor sink `{sink}` failed: {reason}")]
    Sink { sink: String, reason: String },
    #[error("sink returned sealed bytes that do not bind the commitment: {0}")]
    SinkMismatch(String),
    #[error("anchors file is corrupted at line {line}: {reason}")]
    Corrupted { line: usize, reason: String },
    #[error(transparent)]
    Signet(#[from] SignetError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Commitment and sealed bytes
// ---------------------------------------------------------------------------

/// `sha256(JCS({"count", "kind", "prev_anchor", "tip", "v"}))`.
///
/// `count` and `tip` together bind the length and content of the chain, so
/// truncation, replacement and reordering all change the commitment.
/// `prev_anchor` chains the anchors themselves.
pub fn compute_commitment(
    tip: &str,
    count: u64,
    prev_anchor: Option<&str>,
) -> Result<[u8; 32], SignetError> {
    let preimage = serde_json::json!({
        "count": count,
        "kind": COMMITMENT_KIND,
        "prev_anchor": prev_anchor,
        "tip": tip,
        "v": COMMITMENT_VERSION,
    });
    let canonical = canonical::canonicalize(&preimage)?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

pub fn format_commitment(c: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(c))
}

/// Parse `sha256:<64 lowercase hex>`.
pub fn parse_commitment(s: &str) -> Option<[u8; 32]> {
    let hex_part = s.strip_prefix("sha256:")?;
    if hex_part.len() != 64 || !hex_part.bytes().all(is_lower_hex) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_part, &mut out).ok()?;
    Some(out)
}

/// Build `sealed_bytes` for [`SEALED_DEUSPROOF_SEED_V1`].
pub fn deusproof_sealed_bytes(c: &[u8; 32], record_id: &str) -> Vec<u8> {
    format!(":{}:{}", hex::encode(c), record_id).into_bytes()
}

/// Validate the whole `sealed_bytes` structure for `format` and return the
/// commitment it binds. Anything that is not exactly the documented layout
/// is rejected.
pub fn sealed_commitment(format: &str, sealed: &[u8], sink_ref: &str) -> Result<[u8; 32], String> {
    match format {
        SEALED_RAW_SHA256_V1 => {
            let c: [u8; 32] = sealed
                .try_into()
                .map_err(|_| format!("{format}: expected 32 bytes, got {}", sealed.len()))?;
            Ok(c)
        }
        SEALED_DEUSPROOF_SEED_V1 => {
            // ":" HEX64 ":" UUID  ->  1 + 64 + 1 + 36 = 102 bytes
            if sealed.len() != 102 {
                return Err(format!(
                    "{format}: expected 102 bytes, got {}",
                    sealed.len()
                ));
            }
            if sealed[0] != b':' || sealed[65] != b':' {
                return Err(format!(
                    "{format}: separators are not where the layout puts them"
                ));
            }
            let hex_part = &sealed[1..65];
            if !hex_part.iter().copied().all(is_lower_hex) {
                return Err(format!("{format}: commitment is not lowercase hex"));
            }
            let id = &sealed[66..];
            if !is_lower_uuid(id) {
                return Err(format!(
                    "{format}: record id is not a lowercase hyphenated UUID"
                ));
            }
            if id != sink_ref.as_bytes() {
                return Err(format!("{format}: record id does not match sink_ref"));
            }
            let mut c = [0u8; 32];
            hex::decode_to_slice(hex_part, &mut c).map_err(|e| e.to_string())?;
            Ok(c)
        }
        other => Err(format!("unknown sealed format `{other}`")),
    }
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn is_lower_uuid(id: &[u8]) -> bool {
    id.len() == 36
        && id.iter().enumerate().all(|(i, &b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => is_lower_hex(b),
        })
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// Anchors live outside `<signet dir>/audit`, so the audit reader (which
/// reads every `.jsonl` there) never sees them.
pub fn anchors_dir(base: &Path) -> PathBuf {
    base.join("anchors")
}

pub fn anchors_path(base: &Path) -> PathBuf {
    anchors_dir(base).join(ANCHORS_FILE)
}

/// Read every anchor record. A missing file is an empty list.
pub fn read_anchors(base: &Path) -> Result<Vec<AnchorRecord>, AnchorError> {
    let path = anchors_path(base);
    if !path.exists() {
        return Ok(vec![]);
    }
    parse_anchor_lines(&fs::read_to_string(path)?)
}

pub fn parse_anchor_lines(content: &str) -> Result<Vec<AnchorRecord>, AnchorError> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: AnchorRecord =
            serde_json::from_str(line).map_err(|e| AnchorError::Corrupted {
                line: i + 1,
                reason: e.to_string(),
            })?;
        out.push(record);
    }
    Ok(out)
}

fn lock_anchors(base: &Path) -> Result<File, AnchorError> {
    let dir = anchors_dir(base);
    fs::create_dir_all(&dir)?;
    let lock = File::create(dir.join(format!("{ANCHORS_FILE}.lock")))?;
    lock.lock_exclusive()?;
    Ok(lock)
}

fn describe_break(status: &ChainStatus) -> String {
    match &status.break_point {
        Some(b) => format!(
            "{}:{} expected {} got {}",
            b.file, b.line, b.expected_hash, b.actual_hash
        ),
        None => "unknown break".to_string(),
    }
}

/// Anchor the current tip of the local audit chain through `sink`.
///
/// Refuses to anchor a broken chain, an empty log, an already-anchored tip,
/// or a log that is shorter than (or diverges from) what the anchors file
/// already covers — anchoring that state would launder a rollback.
/// On any sink error nothing is written.
pub fn anchor_now(base: &Path, sink: &dyn AnchorSink) -> Result<AnchorRecord, AnchorError> {
    let (status, hashes) = audit::chain_record_hashes(base)?;
    if !status.valid {
        return Err(AnchorError::ChainBroken(describe_break(&status)));
    }
    let tip = hashes.last().cloned().ok_or(AnchorError::EmptyLog)?;
    let count = hashes.len() as u64;

    let lock = lock_anchors(base)?;
    let result = (|| -> Result<AnchorRecord, AnchorError> {
        let existing = read_anchors(base)?;
        for (i, a) in existing.iter().enumerate() {
            let prev = i.checked_sub(1).map(|j| &existing[j]);
            let problems = structure_problems(a, prev, &hashes);
            if !problems.is_empty() {
                return Err(AnchorError::Refused(format!(
                    "existing anchor #{} does not match the local log: {}",
                    i + 1,
                    problems.join("; ")
                )));
            }
        }
        if let Some(last) = existing.last() {
            if last.count == count {
                return Err(AnchorError::AlreadyAnchored(count));
            }
        }
        let prev_anchor = existing.last().map(|a| a.commitment.clone());
        let c = compute_commitment(&tip, count, prev_anchor.as_deref())?;

        let sub = sink.submit(&c).map_err(|reason| AnchorError::Sink {
            sink: sink.id().to_string(),
            reason,
        })?;
        let bound = sealed_commitment(&sub.sealed_format, &sub.sealed_bytes, &sub.sink_ref)
            .map_err(AnchorError::SinkMismatch)?;
        if bound != c {
            return Err(AnchorError::SinkMismatch(
                "sealed bytes carry a different commitment".to_string(),
            ));
        }

        let record = AnchorRecord {
            v: ANCHOR_RECORD_VERSION,
            commitment: format_commitment(&c),
            count,
            tip,
            prev_anchor,
            sink: sink.id().to_string(),
            sink_ref: sub.sink_ref,
            sealed_format: sub.sealed_format,
            sealed_bytes_b64: B64.encode(&sub.sealed_bytes),
            submitted_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            proofs: sub.proofs,
        };
        let line = serde_json::to_string(&record).map_err(SignetError::from)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(anchors_path(base))?;
        writeln!(file, "{line}")?;
        Ok(record)
    })();
    let _ = lock.unlock();
    result
}

/// Ask `sink` for current proofs of every anchor it holds.
///
/// Only `proofs` is ever changed. A refreshed OpenTimestamps proof replaces
/// the stored one only if it parses, covers the same bytes, and does not lose
/// a Bitcoin attestation the stored one had. Returns (updated, errors).
pub fn refresh_anchors(
    base: &Path,
    sink: &dyn AnchorSink,
) -> Result<(usize, Vec<String>), AnchorError> {
    let lock = lock_anchors(base)?;
    let result = (|| -> Result<(usize, Vec<String>), AnchorError> {
        let mut records = read_anchors(base)?;
        let mut updated = 0usize;
        let mut errors = Vec::new();
        for record in records.iter_mut().filter(|r| r.sink == sink.id()) {
            let fresh = match sink.refresh(record) {
                Ok(p) => p,
                Err(e) => {
                    errors.push(format!("{}: {e}", record.commitment));
                    continue;
                }
            };
            if merge_proofs(record, fresh) {
                updated += 1;
            }
        }
        if updated > 0 {
            let path = anchors_path(base);
            let tmp = path.with_extension("jsonl.tmp");
            {
                let mut f = File::create(&tmp)?;
                for r in &records {
                    writeln!(
                        f,
                        "{}",
                        serde_json::to_string(r).map_err(SignetError::from)?
                    )?;
                }
                f.sync_all()?;
            }
            fs::rename(&tmp, &path)?;
        }
        Ok((updated, errors))
    })();
    let _ = lock.unlock();
    result
}

fn merge_proofs(record: &mut AnchorRecord, fresh: Vec<AnchorProof>) -> bool {
    let digest = match B64.decode(&record.sealed_bytes_b64) {
        Ok(sealed) => <[u8; 32]>::from(Sha256::digest(&sealed)),
        Err(_) => return false,
    };
    let mut changed = false;
    for proof in fresh {
        let existing = record.proofs.iter().position(|p| p.kind == proof.kind);
        match proof.kind.as_str() {
            PROOF_OPENTIMESTAMPS => {
                let Some(new) = B64
                    .decode(&proof.data_b64)
                    .ok()
                    .and_then(|b| ots::parse_detached(&b).ok())
                    .filter(|p| p.digest == digest)
                else {
                    continue;
                };
                match existing {
                    None => {
                        record.proofs.push(proof);
                        changed = true;
                    }
                    Some(i) if record.proofs[i].data_b64 != proof.data_b64 => {
                        let old_has_btc = B64
                            .decode(&record.proofs[i].data_b64)
                            .ok()
                            .and_then(|b| ots::parse_detached(&b).ok())
                            .map(|p| p.bitcoin().next().is_some())
                            .unwrap_or(false);
                        if new.bitcoin().next().is_some() || !old_has_btc {
                            record.proofs[i] = proof;
                            changed = true;
                        }
                    }
                    Some(_) => {}
                }
            }
            _ => {
                if existing.is_none() {
                    record.proofs.push(proof);
                    changed = true;
                }
            }
        }
    }
    changed
}

// ---------------------------------------------------------------------------
// Verification (offline)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AnchorStatus {
    /// Structure checks pass and a Bitcoin attestation matched a header from
    /// the configured node.
    Verified,
    /// Structure checks pass; the OpenTimestamps proof is not upgraded yet.
    Pending,
    /// Structure checks pass; the proof is missing or could not be checked.
    Unavailable,
    /// Something does not match. Never counted as success.
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnchorCheck {
    /// 1-based position in the anchors file.
    pub index: usize,
    pub commitment: String,
    pub count: u64,
    pub status: AnchorStatus,
    pub bitcoin_height: Option<u64>,
    pub bitcoin_time: Option<u64>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CheckpointOutcome {
    /// The local log and the local anchors both extend the checkpoint.
    Consistent,
    /// The checkpoint itself is not well-formed.
    Invalid { reason: String },
    /// The local log is shorter than the checkpoint says it was.
    LogTruncated {
        checkpoint_count: u64,
        local_count: u64,
    },
    /// The record the checkpoint anchored has been replaced.
    LogDiverged { count: u64 },
    /// The host presents only anchors older than the checkpoint.
    AnchorsRolledBack {
        checkpoint_count: u64,
        local_latest: Option<u64>,
    },
    /// The local anchor history does not contain the checkpoint.
    AnchorsForked { checkpoint_count: u64 },
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckpointCheck {
    pub commitment: String,
    pub count: u64,
    pub outcome: CheckpointOutcome,
    pub proof_status: AnchorStatus,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Verified,
    Pending,
    Unavailable,
    /// No anchor at all, or more unanchored records than allowed.
    Missing,
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnchorReport {
    pub chain_valid: bool,
    pub chain_records: u64,
    pub anchors: Vec<AnchorCheck>,
    pub latest_verified_count: Option<u64>,
    /// Records after the latest verified anchor (all of them if none).
    pub unanchored_records: u64,
    pub checkpoint: Option<CheckpointCheck>,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
}

#[derive(Default)]
pub struct AnchorVerifyOptions<'a> {
    /// Source of Bitcoin headers. Without one, Bitcoin attestations are
    /// reported as `unavailable`, never as verified.
    pub bitcoin: Option<&'a dyn BitcoinHeaderSource>,
    /// An anchor record the auditor retained outside the host. This is what
    /// makes deletion and rollback detectable.
    pub checkpoint: Option<&'a AnchorRecord>,
    /// Report `missing` when more records than this follow the latest
    /// verified anchor.
    pub max_unanchored: Option<u64>,
}

/// Verify the anchors of the audit log under `base`, offline.
pub fn verify_anchors(
    base: &Path,
    opts: &AnchorVerifyOptions<'_>,
) -> Result<AnchorReport, AnchorError> {
    let (status, hashes) = audit::chain_record_hashes(base)?;
    if !status.valid {
        return Ok(failed_report(
            false,
            status.total_records as u64,
            format!("audit chain is broken: {}", describe_break(&status)),
        ));
    }
    let anchors = match read_anchors(base) {
        Ok(a) => a,
        Err(e @ AnchorError::Corrupted { .. }) => {
            return Ok(failed_report(true, hashes.len() as u64, e.to_string()));
        }
        Err(e) => return Err(e),
    };
    Ok(evaluate(&hashes, &anchors, opts))
}

fn failed_report(chain_valid: bool, records: u64, reason: String) -> AnchorReport {
    AnchorReport {
        chain_valid,
        chain_records: records,
        anchors: vec![],
        latest_verified_count: None,
        unanchored_records: records,
        checkpoint: None,
        verdict: Verdict::Invalid,
        reasons: vec![reason],
    }
}

/// Verify `anchors` against an already-validated chain of record hashes.
pub fn evaluate(
    hashes: &[String],
    anchors: &[AnchorRecord],
    opts: &AnchorVerifyOptions<'_>,
) -> AnchorReport {
    let mut checks = Vec::with_capacity(anchors.len());
    for (i, a) in anchors.iter().enumerate() {
        let prev = i.checked_sub(1).map(|j| &anchors[j]);
        let problems = structure_problems(a, prev, hashes);
        let check = if problems.is_empty() {
            let (status, btc, notes) = proof_status(a, opts.bitcoin);
            AnchorCheck {
                index: i + 1,
                commitment: a.commitment.clone(),
                count: a.count,
                status,
                bitcoin_height: btc.map(|b| b.0),
                bitcoin_time: btc.map(|b| b.1),
                notes,
            }
        } else {
            AnchorCheck {
                index: i + 1,
                commitment: a.commitment.clone(),
                count: a.count,
                status: AnchorStatus::Invalid,
                bitcoin_height: None,
                bitcoin_time: None,
                notes: problems,
            }
        };
        checks.push(check);
    }

    let local = hashes.len() as u64;
    let latest_verified_count = checks
        .iter()
        .filter(|c| c.status == AnchorStatus::Verified)
        .map(|c| c.count)
        .max();
    let unanchored_records = local.saturating_sub(latest_verified_count.unwrap_or(0));
    let checkpoint = opts
        .checkpoint
        .map(|cp| check_checkpoint(cp, hashes, anchors, opts.bitcoin));

    let mut reasons = Vec::new();
    let verdict = if checks.iter().any(|c| c.status == AnchorStatus::Invalid) {
        reasons.push("at least one anchor does not match the local log".to_string());
        Verdict::Invalid
    } else if let Some(cp) = checkpoint
        .as_ref()
        .filter(|cp| cp.outcome != CheckpointOutcome::Consistent)
    {
        reasons.push(format!("auditor checkpoint: {:?}", cp.outcome));
        Verdict::Invalid
    } else if checkpoint
        .as_ref()
        .is_some_and(|cp| cp.proof_status == AnchorStatus::Invalid)
    {
        reasons.push("auditor checkpoint carries an invalid proof".to_string());
        Verdict::Invalid
    } else if checks.is_empty() {
        reasons.push("no anchors: nothing outside this host vouches for the log".to_string());
        Verdict::Missing
    } else if opts
        .max_unanchored
        .is_some_and(|max| unanchored_records > max)
    {
        reasons.push(format!(
            "{unanchored_records} records follow the latest verified anchor (allowed: {})",
            opts.max_unanchored.unwrap_or_default()
        ));
        Verdict::Missing
    } else {
        match checks.last().map(|c| c.status) {
            Some(AnchorStatus::Verified) => Verdict::Verified,
            Some(AnchorStatus::Pending) => {
                reasons.push("latest anchor is pending".to_string());
                Verdict::Pending
            }
            _ => {
                reasons.push("latest anchor could not be checked".to_string());
                Verdict::Unavailable
            }
        }
    };
    if opts.checkpoint.is_none() {
        reasons.push(
            "no auditor checkpoint given: deletion or rollback of the log together with its anchors cannot be ruled out"
                .to_string(),
        );
    }

    AnchorReport {
        chain_valid: true,
        chain_records: local,
        anchors: checks,
        latest_verified_count,
        unanchored_records,
        checkpoint,
        verdict,
        reasons,
    }
}

/// Checks that need nothing but the record itself.
fn self_consistency_problems(a: &AnchorRecord) -> Vec<String> {
    let mut p = Vec::new();
    if a.v != ANCHOR_RECORD_VERSION {
        p.push(format!("unsupported anchor record version {}", a.v));
    }
    if a.count == 0 {
        p.push("anchor covers zero records".to_string());
    }
    let Some(stored) = parse_commitment(&a.commitment) else {
        p.push("commitment is not `sha256:<64 lowercase hex>`".to_string());
        return p;
    };
    match compute_commitment(&a.tip, a.count, a.prev_anchor.as_deref()) {
        Ok(c) if c == stored => {}
        Ok(_) => p.push("commitment does not match tip, count and prev_anchor".to_string()),
        Err(e) => p.push(format!("cannot recompute commitment: {e}")),
    }
    match B64.decode(&a.sealed_bytes_b64) {
        Ok(sealed) => match sealed_commitment(&a.sealed_format, &sealed, &a.sink_ref) {
            Ok(c) if c == stored => {}
            Ok(_) => p.push("sealed bytes carry a different commitment".to_string()),
            Err(e) => p.push(e),
        },
        Err(_) => p.push("sealed_bytes_b64 is not base64".to_string()),
    }
    p
}

fn structure_problems(
    a: &AnchorRecord,
    prev: Option<&AnchorRecord>,
    hashes: &[String],
) -> Vec<String> {
    let mut p = self_consistency_problems(a);
    let local = hashes.len() as u64;
    if a.count > local {
        p.push(format!(
            "anchor covers {} records but the local log has {local}: log truncated or replaced",
            a.count
        ));
    } else if a.count > 0 && hashes[(a.count - 1) as usize] != a.tip {
        p.push(format!(
            "record #{} differs from the anchored tip: log rewritten",
            a.count
        ));
    }
    match prev {
        None if a.prev_anchor.is_some() => {
            p.push("first anchor references a previous anchor that is not here".to_string())
        }
        None => {}
        Some(prev) => {
            if a.prev_anchor.as_deref() != Some(prev.commitment.as_str()) {
                p.push("prev_anchor does not point at the anchor before it".to_string());
            }
            if a.count <= prev.count {
                p.push("anchor does not cover more records than the one before it".to_string());
            }
        }
    }
    p
}

fn proof_status(
    a: &AnchorRecord,
    bitcoin: Option<&dyn BitcoinHeaderSource>,
) -> (AnchorStatus, Option<(u64, u64)>, Vec<String>) {
    let mut notes = Vec::new();
    let Ok(sealed) = B64.decode(&a.sealed_bytes_b64) else {
        return (
            AnchorStatus::Invalid,
            None,
            vec!["sealed_bytes_b64 is not base64".into()],
        );
    };
    let digest: [u8; 32] = Sha256::digest(&sealed).into();

    let mut invalid = false;
    let mut pending = false;
    let mut verified: Option<(u64, u64)> = None;
    let mut saw_ots = false;

    for proof in &a.proofs {
        match proof.kind.as_str() {
            PROOF_RFC3161 => notes.push(
                "rfc3161 token present; not checked by this version (TSA chain pinning is follow-up work)"
                    .to_string(),
            ),
            PROOF_OPENTIMESTAMPS => {
                saw_ots = true;
                let Ok(bytes) = B64.decode(&proof.data_b64) else {
                    invalid = true;
                    notes.push("opentimestamps proof is not base64".into());
                    continue;
                };
                let parsed = match ots::parse_detached(&bytes) {
                    Ok(p) => p,
                    Err(e @ ots::OtsError::UnsupportedOp(_)) => {
                        notes.push(format!("opentimestamps proof not checkable here: {e}"));
                        continue;
                    }
                    Err(e) => {
                        invalid = true;
                        notes.push(format!("opentimestamps proof is malformed: {e}"));
                        continue;
                    }
                };
                if parsed.digest != digest {
                    invalid = true;
                    notes.push("opentimestamps proof covers different bytes than sealed_bytes".into());
                    continue;
                }
                let attested: Vec<(u64, &[u8])> = parsed.bitcoin().collect();
                if attested.is_empty() {
                    if parsed.has_pending() {
                        pending = true;
                        notes.push("opentimestamps proof is pending (no Bitcoin attestation yet)".into());
                    } else {
                        notes.push("opentimestamps proof has no Bitcoin attestation".into());
                    }
                    continue;
                }
                let Some(source) = bitcoin else {
                    let heights: Vec<String> = attested.iter().map(|(h, _)| h.to_string()).collect();
                    notes.push(format!(
                        "Bitcoin attestation at height {} not checked: no Bitcoin node configured",
                        heights.join(", ")
                    ));
                    continue;
                };
                for (height, message) in attested {
                    match source.header_at(height) {
                        Ok(header) if message == header.merkle_root.as_slice() => {
                            verified = Some((height, header.time));
                        }
                        Ok(_) => {
                            invalid = true;
                            notes.push(format!(
                                "block {height} does not commit to this proof (merkle root mismatch)"
                            ));
                        }
                        Err(e) => notes.push(format!("block {height}: header unavailable: {e}")),
                    }
                }
            }
            other => notes.push(format!("unknown proof kind `{other}` ignored")),
        }
    }
    if !saw_ots {
        notes.push("no opentimestamps proof stored yet".to_string());
    }
    let status = if invalid {
        AnchorStatus::Invalid
    } else if verified.is_some() {
        AnchorStatus::Verified
    } else if pending {
        AnchorStatus::Pending
    } else {
        AnchorStatus::Unavailable
    };
    (status, if invalid { None } else { verified }, notes)
}

fn check_checkpoint(
    cp: &AnchorRecord,
    hashes: &[String],
    anchors: &[AnchorRecord],
    bitcoin: Option<&dyn BitcoinHeaderSource>,
) -> CheckpointCheck {
    let problems = self_consistency_problems(cp);
    let (proof_status, _, notes) = if problems.is_empty() {
        proof_status(cp, bitcoin)
    } else {
        (AnchorStatus::Invalid, None, vec![])
    };
    let local = hashes.len() as u64;
    let outcome = if !problems.is_empty() {
        CheckpointOutcome::Invalid {
            reason: problems.join("; "),
        }
    } else if local < cp.count {
        CheckpointOutcome::LogTruncated {
            checkpoint_count: cp.count,
            local_count: local,
        }
    } else if hashes[(cp.count - 1) as usize] != cp.tip {
        CheckpointOutcome::LogDiverged { count: cp.count }
    } else if anchors.iter().any(|a| a.commitment == cp.commitment) {
        CheckpointOutcome::Consistent
    } else {
        let local_latest = anchors.iter().map(|a| a.count).max();
        let rolled_back = match local_latest {
            None => true,
            Some(c) => c < cp.count,
        };
        if rolled_back {
            CheckpointOutcome::AnchorsRolledBack {
                checkpoint_count: cp.count,
                local_latest,
            }
        } else {
            CheckpointOutcome::AnchorsForked {
                checkpoint_count: cp.count,
            }
        }
    };
    CheckpointCheck {
        commitment: cp.commitment.clone(),
        count: cp.count,
        outcome,
        proof_status,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    // -- helpers ------------------------------------------------------------

    fn receipt(i: u32) -> serde_json::Value {
        serde_json::json!({
            "v": 1,
            "id": format!("rec_{i}"),
            "ts": format!("2026-11-05T10:{:02}:{:02}Z", i / 60, i % 60),
            "action": {"tool": "demo", "target": "t"},
        })
    }

    fn log_with(n: u32) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..n {
            audit::append(dir.path(), &receipt(i)).unwrap();
        }
        dir
    }

    fn audit_file(dir: &Path) -> PathBuf {
        let mut files: Vec<PathBuf> = fs::read_dir(dir.join("audit"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        files.pop().unwrap()
    }

    /// Fake OpenTimestamps calendar: proof = sha256 op to a Bitcoin
    /// attestation at a chosen height, or a pending attestation.
    fn ots_proof(digest: &[u8; 32], bitcoin_height: Option<u64>) -> (Vec<u8>, [u8; 32]) {
        let mut v = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94".to_vec();
        v.push(0x01);
        v.push(0x08);
        v.extend_from_slice(digest);
        v.push(0x08); // sha256 -> "merkle root"
        let root: [u8; 32] = Sha256::digest(digest).into();
        v.push(0x00);
        match bitcoin_height {
            Some(h) => {
                v.extend_from_slice(&[0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
                let mut payload = Vec::new();
                let mut x = h;
                loop {
                    let b = (x & 0x7f) as u8;
                    x >>= 7;
                    if x == 0 {
                        payload.push(b);
                        break;
                    }
                    payload.push(b | 0x80);
                }
                v.push(payload.len() as u8);
                v.extend_from_slice(&payload);
            }
            None => {
                v.extend_from_slice(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
                let uri = b"https://calendar.example";
                v.push((uri.len() + 1) as u8);
                v.push(uri.len() as u8);
                v.extend_from_slice(uri);
            }
        }
        (v, root)
    }

    /// In-memory sink with the DEUSPROOF layout and a fake chain.
    struct FakeSink {
        fail: bool,
        confirmed: bool,
        next_id: RefCell<u32>,
        roots: RefCell<HashMap<u64, [u8; 32]>>,
    }

    impl FakeSink {
        fn new() -> Self {
            FakeSink {
                fail: false,
                confirmed: true,
                next_id: RefCell::new(0),
                roots: RefCell::new(HashMap::new()),
            }
        }
        fn record_id(&self) -> String {
            let mut n = self.next_id.borrow_mut();
            *n += 1;
            format!("00000000-0000-4000-8000-{:012x}", *n)
        }
        fn proofs_for(&self, sealed: &[u8], height: u64) -> Vec<AnchorProof> {
            let digest: [u8; 32] = Sha256::digest(sealed).into();
            let (ots, root) = ots_proof(&digest, self.confirmed.then_some(height));
            self.roots.borrow_mut().insert(height, root);
            vec![AnchorProof {
                kind: PROOF_OPENTIMESTAMPS.into(),
                data_b64: B64.encode(ots),
            }]
        }
    }

    impl AnchorSink for FakeSink {
        fn id(&self) -> &str {
            "fake"
        }
        fn submit(&self, c: &[u8; 32]) -> Result<SinkSubmission, String> {
            if self.fail {
                return Err("connection refused".into());
            }
            let id = self.record_id();
            let sealed = deusproof_sealed_bytes(c, &id);
            let height = 900_000 + u64::from(*self.next_id.borrow());
            Ok(SinkSubmission {
                proofs: self.proofs_for(&sealed, height),
                sink_ref: id,
                sealed_format: SEALED_DEUSPROOF_SEED_V1.into(),
                sealed_bytes: sealed,
            })
        }
        fn refresh(&self, _record: &AnchorRecord) -> Result<Vec<AnchorProof>, String> {
            Ok(vec![])
        }
    }

    struct FakeNode<'a>(&'a FakeSink);

    impl BitcoinHeaderSource for FakeNode<'_> {
        fn header_at(&self, height: u64) -> Result<BlockHeader, String> {
            self.0
                .roots
                .borrow()
                .get(&height)
                .map(|r| BlockHeader {
                    merkle_root: *r,
                    time: 1_793_000_000 + height,
                })
                .ok_or_else(|| format!("no block {height}"))
        }
    }

    fn verify(dir: &Path, sink: &FakeSink, checkpoint: Option<&AnchorRecord>) -> AnchorReport {
        let node = FakeNode(sink);
        verify_anchors(
            dir,
            &AnchorVerifyOptions {
                bitcoin: Some(&node),
                checkpoint,
                max_unanchored: None,
            },
        )
        .unwrap()
    }

    // -- commitment and sealed bytes ----------------------------------------

    #[test]
    fn commitment_binds_tip_count_and_prev() {
        let base = compute_commitment("sha256:aa", 3, None).unwrap();
        assert_ne!(base, compute_commitment("sha256:ab", 3, None).unwrap());
        assert_ne!(base, compute_commitment("sha256:aa", 4, None).unwrap());
        assert_ne!(
            base,
            compute_commitment("sha256:aa", 3, Some("sha256:00")).unwrap()
        );
        assert_eq!(base, compute_commitment("sha256:aa", 3, None).unwrap());
    }

    #[test]
    fn commitment_preimage_is_pinned() {
        // Pins the exact preimage bytes so another implementation can match them.
        let preimage = r#"{"count":2,"kind":"signet-audit-anchor","prev_anchor":null,"tip":"sha256:00","v":1}"#;
        let expected: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
        assert_eq!(compute_commitment("sha256:00", 2, None).unwrap(), expected);
    }

    #[test]
    fn deusproof_layout_is_validated_in_full() {
        let c = [0xabu8; 32];
        let id = "0baa3414-c57b-4fe5-bebf-15226f7cdd1d";
        let good = deusproof_sealed_bytes(&c, id);
        assert_eq!(
            sealed_commitment(SEALED_DEUSPROOF_SEED_V1, &good, id).unwrap(),
            c
        );
        // Contains C but is not the layout: prefix with a prompt hash.
        let mut with_prefix = b"ff".to_vec();
        with_prefix.extend_from_slice(&good);
        assert!(sealed_commitment(SEALED_DEUSPROOF_SEED_V1, &with_prefix, id).is_err());
        // Uppercase hex.
        let upper = good.to_ascii_uppercase();
        assert!(sealed_commitment(SEALED_DEUSPROOF_SEED_V1, &upper, &id.to_uppercase()).is_err());
        // Another record's id.
        assert!(sealed_commitment(
            SEALED_DEUSPROOF_SEED_V1,
            &good,
            "0baa3414-c57b-4fe5-bebf-15226f7cdd1e"
        )
        .is_err());
        // Raw layout is exactly 32 bytes.
        assert_eq!(sealed_commitment(SEALED_RAW_SHA256_V1, &c, "").unwrap(), c);
        assert!(sealed_commitment(SEALED_RAW_SHA256_V1, &good, "").is_err());
        assert!(sealed_commitment("other", &good, id).is_err());
    }

    #[test]
    fn real_deusproof_seed_fixture_matches_layout() {
        let seed = include_bytes!(
            "../tests/fixtures/anchor/deusproof-0baa3414-c57b-4fe5-bebf-15226f7cdd1d.seed"
        );
        let c = sealed_commitment(
            SEALED_DEUSPROOF_SEED_V1,
            seed,
            "0baa3414-c57b-4fe5-bebf-15226f7cdd1d",
        )
        .unwrap();
        assert_eq!(
            hex::encode(c),
            "b02e2ea0712c718392b3fc9d6ec2b9a13ed5394f7c8e9cc9b8b33c121e4df8a5"
        );
        let ots = include_bytes!(
            "../tests/fixtures/anchor/deusproof-0baa3414-c57b-4fe5-bebf-15226f7cdd1d.ots"
        );
        let parsed = ots::parse_detached(ots).unwrap();
        let digest: [u8; 32] = Sha256::digest(seed).into();
        assert_eq!(parsed.digest, digest);
        assert!(parsed.bitcoin().next().is_some());
    }

    /// A real proof issued by DEUSPROOF on 2026-11-02, upgraded by the
    /// OpenTimestamps calendars into Bitcoin block 974402. The header values
    /// below were read from that block (merkle root shown in internal byte
    /// order, i.e. reversed from explorer display).
    #[test]
    fn real_proof_verifies_against_the_real_block_header() {
        struct Fixed([u8; 32]);
        impl BitcoinHeaderSource for Fixed {
            fn header_at(&self, height: u64) -> Result<BlockHeader, String> {
                if height != 974_402 {
                    return Err(format!("unexpected height {height}"));
                }
                Ok(BlockHeader {
                    merkle_root: self.0,
                    time: 1_793_720_933,
                })
            }
        }
        let id = "0baa3414-c57b-4fe5-bebf-15226f7cdd1d";
        let seed = include_bytes!(
            "../tests/fixtures/anchor/deusproof-0baa3414-c57b-4fe5-bebf-15226f7cdd1d.seed"
        );
        let ots = include_bytes!(
            "../tests/fixtures/anchor/deusproof-0baa3414-c57b-4fe5-bebf-15226f7cdd1d.ots"
        );
        let record = AnchorRecord {
            v: ANCHOR_RECORD_VERSION,
            commitment: "sha256:b02e2ea0712c718392b3fc9d6ec2b9a13ed5394f7c8e9cc9b8b33c121e4df8a5"
                .into(),
            count: 1,
            tip: String::new(),
            prev_anchor: None,
            sink: "deusproof".into(),
            sink_ref: id.into(),
            sealed_format: SEALED_DEUSPROOF_SEED_V1.into(),
            sealed_bytes_b64: B64.encode(seed),
            submitted_at: String::new(),
            proofs: vec![AnchorProof {
                kind: PROOF_OPENTIMESTAMPS.into(),
                data_b64: B64.encode(ots),
            }],
        };
        let mut root = [0u8; 32];
        hex::decode_to_slice(
            "8be3650b21ec144cb5170f08051050e0a7a116d94d3ffd01a5916c5ebc5d2064",
            &mut root,
        )
        .unwrap();

        let (status, btc, _) = proof_status(&record, Some(&Fixed(root)));
        assert_eq!(status, AnchorStatus::Verified);
        assert_eq!(btc, Some((974_402, 1_793_720_933)));

        let mut wrong = root;
        wrong[0] ^= 1;
        let (status, _, notes) = proof_status(&record, Some(&Fixed(wrong)));
        assert_eq!(status, AnchorStatus::Invalid, "{notes:?}");

        let (status, _, _) = proof_status(&record, None);
        assert_eq!(status, AnchorStatus::Unavailable);
    }

    // -- anchoring ----------------------------------------------------------

    #[test]
    fn anchor_then_verify_end_to_end() {
        let dir = log_with(3);
        let sink = FakeSink::new();
        let first = anchor_now(dir.path(), &sink).unwrap();
        assert_eq!(first.count, 3);
        assert_eq!(first.prev_anchor, None);
        audit::append(dir.path(), &receipt(3)).unwrap();
        let second = anchor_now(dir.path(), &sink).unwrap();
        assert_eq!(
            second.prev_anchor.as_deref(),
            Some(first.commitment.as_str())
        );

        let report = verify(dir.path(), &sink, Some(&second));
        assert_eq!(report.verdict, Verdict::Verified, "{report:?}");
        assert_eq!(report.latest_verified_count, Some(4));
        assert_eq!(report.unanchored_records, 0);
        assert_eq!(
            report.checkpoint.unwrap().outcome,
            CheckpointOutcome::Consistent
        );
    }

    #[test]
    fn anchors_live_outside_the_audit_dir() {
        let dir = log_with(2);
        anchor_now(dir.path(), &FakeSink::new()).unwrap();
        assert!(anchors_path(dir.path()).exists());
        assert!(!anchors_path(dir.path()).starts_with(dir.path().join("audit")));
        assert!(audit::verify_chain(dir.path()).unwrap().valid);
        assert_eq!(
            audit::query(dir.path(), &Default::default()).unwrap().len(),
            2
        );
    }

    #[test]
    fn sink_failure_leaves_log_and_anchors_untouched() {
        let dir = log_with(2);
        let before = fs::read(audit_file(dir.path())).unwrap();
        let mut sink = FakeSink::new();
        sink.fail = true;
        let err = anchor_now(dir.path(), &sink).unwrap_err();
        assert!(matches!(err, AnchorError::Sink { .. }), "{err}");
        assert_eq!(fs::read(audit_file(dir.path())).unwrap(), before);
        assert!(read_anchors(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn sink_returning_other_commitment_is_rejected() {
        struct Liar;
        impl AnchorSink for Liar {
            fn id(&self) -> &str {
                "liar"
            }
            fn submit(&self, _c: &[u8; 32]) -> Result<SinkSubmission, String> {
                let id = "00000000-0000-4000-8000-000000000001".to_string();
                Ok(SinkSubmission {
                    sealed_bytes: deusproof_sealed_bytes(&[9u8; 32], &id),
                    sink_ref: id,
                    sealed_format: SEALED_DEUSPROOF_SEED_V1.into(),
                    proofs: vec![],
                })
            }
            fn refresh(&self, _r: &AnchorRecord) -> Result<Vec<AnchorProof>, String> {
                Ok(vec![])
            }
        }
        let dir = log_with(1);
        assert!(matches!(
            anchor_now(dir.path(), &Liar),
            Err(AnchorError::SinkMismatch(_))
        ));
        assert!(read_anchors(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn refuses_empty_log_and_repeated_tip() {
        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            anchor_now(empty.path(), &FakeSink::new()),
            Err(AnchorError::EmptyLog)
        ));
        let dir = log_with(1);
        let sink = FakeSink::new();
        anchor_now(dir.path(), &sink).unwrap();
        assert!(matches!(
            anchor_now(dir.path(), &sink),
            Err(AnchorError::AlreadyAnchored(1))
        ));
    }

    // -- tampering ----------------------------------------------------------

    #[test]
    fn truncation_after_an_anchor_is_invalid() {
        let dir = log_with(3);
        let sink = FakeSink::new();
        anchor_now(dir.path(), &sink).unwrap();
        let file = audit_file(dir.path());
        let content = fs::read_to_string(&file).unwrap();
        let kept: Vec<&str> = content.lines().take(2).collect();
        fs::write(&file, kept.join("\n") + "\n").unwrap();

        let report = verify(dir.path(), &sink, None);
        assert_eq!(report.verdict, Verdict::Invalid);
        assert!(report.anchors[0]
            .notes
            .iter()
            .any(|n| n.contains("truncated")));
        // And the host cannot launder it by anchoring the shorter log.
        assert!(matches!(
            anchor_now(dir.path(), &sink),
            Err(AnchorError::Refused(_))
        ));
    }

    #[test]
    fn replacing_a_record_and_rehashing_is_invalid() {
        let dir = log_with(3);
        let sink = FakeSink::new();
        anchor_now(dir.path(), &sink).unwrap();
        // Rebuild the whole log with a different second record: the chain is
        // internally valid again, but no longer the anchored one.
        fs::remove_dir_all(dir.path().join("audit")).unwrap();
        for i in 0..3 {
            let mut r = receipt(i);
            if i == 1 {
                r["action"]["target"] = "other".into();
            }
            audit::append(dir.path(), &r).unwrap();
        }
        assert!(audit::verify_chain(dir.path()).unwrap().valid);
        let report = verify(dir.path(), &sink, None);
        assert_eq!(report.verdict, Verdict::Invalid);
        assert!(report.anchors[0]
            .notes
            .iter()
            .any(|n| n.contains("rewritten")));
    }

    #[test]
    fn editing_a_record_in_place_breaks_the_chain() {
        let dir = log_with(2);
        let sink = FakeSink::new();
        anchor_now(dir.path(), &sink).unwrap();
        let file = audit_file(dir.path());
        let content = fs::read_to_string(&file).unwrap().replace("\"t\"", "\"x\"");
        fs::write(&file, content).unwrap();
        let report = verify(dir.path(), &sink, None);
        assert!(!report.chain_valid);
        assert_eq!(report.verdict, Verdict::Invalid);
    }

    #[test]
    fn deleting_the_anchors_file_is_missing_not_success() {
        let dir = log_with(2);
        let sink = FakeSink::new();
        let anchor = anchor_now(dir.path(), &sink).unwrap();
        fs::remove_file(anchors_path(dir.path())).unwrap();

        let report = verify(dir.path(), &sink, None);
        assert_eq!(report.verdict, Verdict::Missing);
        // With the auditor's retained checkpoint it is a rollback.
        let report = verify(dir.path(), &sink, Some(&anchor));
        assert_eq!(report.verdict, Verdict::Invalid);
        assert!(matches!(
            report.checkpoint.unwrap().outcome,
            CheckpointOutcome::AnchorsRolledBack { .. }
        ));
    }

    #[test]
    fn deleting_log_and_anchors_together_needs_the_checkpoint() {
        let dir = log_with(2);
        let sink = FakeSink::new();
        let anchor = anchor_now(dir.path(), &sink).unwrap();
        fs::remove_dir_all(dir.path().join("audit")).unwrap();
        fs::remove_file(anchors_path(dir.path())).unwrap();

        assert_eq!(verify(dir.path(), &sink, None).verdict, Verdict::Missing);
        let report = verify(dir.path(), &sink, Some(&anchor));
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(
            report.checkpoint.unwrap().outcome,
            CheckpointOutcome::LogTruncated {
                checkpoint_count: 2,
                local_count: 0
            }
        );
    }

    #[test]
    fn rollback_to_an_older_valid_checkpoint_is_caught_by_a_newer_one() {
        let dir = log_with(2);
        let sink = FakeSink::new();
        anchor_now(dir.path(), &sink).unwrap();
        // Snapshot the older, fully valid state.
        let old_log = fs::read(audit_file(dir.path())).unwrap();
        let old_anchors = fs::read(anchors_path(dir.path())).unwrap();

        audit::append(dir.path(), &receipt(2)).unwrap();
        let newer = anchor_now(dir.path(), &sink).unwrap();

        // The host restores the older snapshot: on its own it verifies.
        fs::write(audit_file(dir.path()), &old_log).unwrap();
        fs::write(anchors_path(dir.path()), &old_anchors).unwrap();
        assert_eq!(verify(dir.path(), &sink, None).verdict, Verdict::Verified);

        // The auditor kept the newer checkpoint.
        let report = verify(dir.path(), &sink, Some(&newer));
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(
            report.checkpoint.unwrap().outcome,
            CheckpointOutcome::LogTruncated {
                checkpoint_count: 3,
                local_count: 2
            }
        );
    }

    #[test]
    fn anchors_rolled_back_with_log_intact() {
        let dir = log_with(2);
        let sink = FakeSink::new();
        anchor_now(dir.path(), &sink).unwrap();
        let old_anchors = fs::read(anchors_path(dir.path())).unwrap();
        audit::append(dir.path(), &receipt(2)).unwrap();
        let newer = anchor_now(dir.path(), &sink).unwrap();
        fs::write(anchors_path(dir.path()), &old_anchors).unwrap();

        let report = verify(dir.path(), &sink, Some(&newer));
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(
            report.checkpoint.unwrap().outcome,
            CheckpointOutcome::AnchorsRolledBack {
                checkpoint_count: 3,
                local_latest: Some(2)
            }
        );
    }

    #[test]
    fn tampered_sealed_bytes_are_invalid() {
        let dir = log_with(2);
        let sink = FakeSink::new();
        let mut a = anchor_now(dir.path(), &sink).unwrap();
        let mut sealed = B64.decode(&a.sealed_bytes_b64).unwrap();
        sealed[1] = if sealed[1] == b'0' { b'1' } else { b'0' };
        a.sealed_bytes_b64 = B64.encode(sealed);
        fs::write(
            anchors_path(dir.path()),
            serde_json::to_string(&a).unwrap() + "\n",
        )
        .unwrap();
        assert_eq!(verify(dir.path(), &sink, None).verdict, Verdict::Invalid);
    }

    #[test]
    fn unknown_fields_and_stored_state_are_rejected() {
        let dir = log_with(1);
        let sink = FakeSink::new();
        let a = anchor_now(dir.path(), &sink).unwrap();
        let mut v = serde_json::to_value(&a).unwrap();
        v["state"] = "verified".into();
        fs::write(anchors_path(dir.path()), v.to_string() + "\n").unwrap();
        let report = verify(dir.path(), &sink, None);
        assert_eq!(report.verdict, Verdict::Invalid);
    }

    // -- proof states -------------------------------------------------------

    #[test]
    fn pending_proof_is_pending_not_success() {
        let dir = log_with(1);
        let mut sink = FakeSink::new();
        sink.confirmed = false;
        anchor_now(dir.path(), &sink).unwrap();
        let report = verify(dir.path(), &sink, None);
        assert_eq!(report.verdict, Verdict::Pending);
        assert_eq!(report.latest_verified_count, None);
    }

    #[test]
    fn missing_proof_and_missing_node_are_unavailable() {
        let dir = log_with(1);
        let sink = FakeSink::new();
        let mut a = anchor_now(dir.path(), &sink).unwrap();

        // Bitcoin attestation present but no node configured.
        let report = verify_anchors(dir.path(), &AnchorVerifyOptions::default()).unwrap();
        assert_eq!(report.verdict, Verdict::Unavailable);

        // No proof stored at all.
        a.proofs.clear();
        fs::write(
            anchors_path(dir.path()),
            serde_json::to_string(&a).unwrap() + "\n",
        )
        .unwrap();
        assert_eq!(
            verify(dir.path(), &sink, None).verdict,
            Verdict::Unavailable
        );
    }

    #[test]
    fn wrong_block_is_invalid() {
        let dir = log_with(1);
        let sink = FakeSink::new();
        let a = anchor_now(dir.path(), &sink).unwrap();
        let report = verify(dir.path(), &sink, None);
        let height = report.anchors[0].bitcoin_height.unwrap();
        sink.roots.borrow_mut().insert(height, [0u8; 32]);
        let report = verify(dir.path(), &sink, Some(&a));
        assert_eq!(report.verdict, Verdict::Invalid);
    }

    #[test]
    fn max_unanchored_reports_missing() {
        let dir = log_with(1);
        let sink = FakeSink::new();
        anchor_now(dir.path(), &sink).unwrap();
        for i in 1..4 {
            audit::append(dir.path(), &receipt(i)).unwrap();
        }
        let node = FakeNode(&sink);
        let report = verify_anchors(
            dir.path(),
            &AnchorVerifyOptions {
                bitcoin: Some(&node),
                checkpoint: None,
                max_unanchored: Some(2),
            },
        )
        .unwrap();
        assert_eq!(report.unanchored_records, 3);
        assert_eq!(report.verdict, Verdict::Missing);
    }

    #[test]
    fn refresh_upgrades_pending_and_never_downgrades() {
        struct Upgrader {
            confirmed: bool,
        }
        impl AnchorSink for Upgrader {
            fn id(&self) -> &str {
                "fake"
            }
            fn submit(&self, _c: &[u8; 32]) -> Result<SinkSubmission, String> {
                Err("unused".into())
            }
            fn refresh(&self, r: &AnchorRecord) -> Result<Vec<AnchorProof>, String> {
                let sealed = B64.decode(&r.sealed_bytes_b64).unwrap();
                let digest: [u8; 32] = Sha256::digest(&sealed).into();
                let (ots, _) = ots_proof(&digest, self.confirmed.then_some(900_001));
                Ok(vec![AnchorProof {
                    kind: PROOF_OPENTIMESTAMPS.into(),
                    data_b64: B64.encode(ots),
                }])
            }
        }
        let dir = log_with(1);
        let mut pending_sink = FakeSink::new();
        pending_sink.confirmed = false;
        anchor_now(dir.path(), &pending_sink).unwrap();

        let (updated, errors) = refresh_anchors(dir.path(), &Upgrader { confirmed: true }).unwrap();
        assert_eq!((updated, errors.len()), (1, 0));
        let after_upgrade = fs::read(anchors_path(dir.path())).unwrap();

        // A later refresh that only has a pending proof must not replace it.
        let (updated, _) = refresh_anchors(dir.path(), &Upgrader { confirmed: false }).unwrap();
        assert_eq!(updated, 0);
        assert_eq!(fs::read(anchors_path(dir.path())).unwrap(), after_upgrade);
    }
}
