//! Revocation — issuer-signed records over delegation tokens and
//! authorization decisions (spec §4).
//!
//! The revocation *status* is two-valued: `Revoked` or `Unknown`. Absence of
//! a record is never evidence of validity — the overall verification result
//! is the pair *(cryptographic validity) × (revocation status)*. A provable
//! `Valid` status would require signed complete lists (Phase 2/3); adding
//! that variant later is additive.
//!
//! Only the artifact's issuer can revoke it — the delegator for a token, the
//! authority for a decision — checkable fully offline against the embedded
//! pubkeys. Records live in a local JSONL file; each is individually signed,
//! so content tampering is detectable. Offline, revocation effectiveness is
//! bounded by record propagation (same honesty model as `FileNonceChecker`).

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use serde::{Deserialize, Serialize};

use crate::authorization::AuthorizationDecision;
use crate::canonical;
use crate::delegation::{
    current_timestamp, format_sig, generate_nonce, parse_signature, parse_verifying_key,
    DelegationToken,
};
use crate::error::SignetError;

pub const REVOCATION_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    DelegationToken,
    AuthorizationDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub v: u8, // always 1
    pub artifact_type: ArtifactType,
    pub artifact_id: String, // DelegationToken.id or AuthorizationDecision.decision_id
    pub revoked_by: String,  // principal URI of the issuer
    pub revoked_at: String,  // RFC 3339 UTC (Z)
    #[serde(default)]
    pub reason: String,
    pub nonce: String, // "rnd_<hex>"
    pub sig: String,   // Ed25519 by the artifact's ISSUER, over the record body below
}

/// Two-value status: absence of a record is never evidence of validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    Revoked { at: String, by: String },
    Unknown,
}

fn invalid_record(msg: impl std::fmt::Display) -> SignetError {
    SignetError::InvalidReceipt(format!("malformed revocation record: {msg}"))
}

/// Build the signable JSON for a record. Excludes `sig` (derived from it).
fn build_record_signable(rec: &RevocationRecord) -> Result<serde_json::Value, SignetError> {
    if rec.v != REVOCATION_VERSION {
        return Err(invalid_record(format!("unsupported version {}", rec.v)));
    }
    Ok(serde_json::json!({
        "v": rec.v,
        "artifact_type": rec.artifact_type,
        "artifact_id": rec.artifact_id,
        "revoked_by": rec.revoked_by,
        "revoked_at": rec.revoked_at,
        "reason": rec.reason,
        "nonce": rec.nonce,
    }))
}

/// Compose and issuer-sign a revocation record.
pub fn sign_revocation(
    issuer_key: &SigningKey,
    artifact_type: ArtifactType,
    artifact_id: &str,
    revoked_by: &str,
    reason: &str,
) -> Result<RevocationRecord, SignetError> {
    if artifact_id.is_empty() {
        return Err(invalid_record("artifact_id must be non-empty"));
    }
    crate::principal::validate_principal(revoked_by)?;

    let unsigned = RevocationRecord {
        v: REVOCATION_VERSION,
        artifact_type,
        artifact_id: artifact_id.to_string(),
        revoked_by: revoked_by.to_string(),
        revoked_at: current_timestamp(),
        reason: reason.to_string(),
        nonce: generate_nonce(),
        sig: String::new(),
    };

    let canonical_bytes = canonical::canonicalize(&build_record_signable(&unsigned)?)?;
    let signature = issuer_key.sign(canonical_bytes.as_bytes());
    Ok(RevocationRecord {
        sig: format_sig(&signature.to_bytes()),
        ..unsigned
    })
}

/// Verify a record's internal consistency: signable reconstructs, the
/// signature decodes, and it verifies against `issuer_pubkey`.
/// (Which issuer is legitimate is decided by pairing with the artifact —
/// see `check_revocation`.)
pub fn verify_revocation_record(
    record: &RevocationRecord,
    issuer_pubkey: &ed25519_dalek::VerifyingKey,
) -> Result<(), SignetError> {
    let signature = parse_signature(&record.sig).map_err(invalid_record)?;
    let canonical_bytes = canonical::canonicalize(&build_record_signable(record)?)?;
    issuer_pubkey
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| invalid_record("signature does not verify against the issuer key"))
}

/// Tri-state check over a set of artifacts. Malformed records —
/// undecodable signatures, or signatures that fail against the artifact's
/// own issuer — are a hard error (fail closed); records referencing
/// artifacts not in the input set are ignored (they belong to other
/// verifications). No matching record → `Unknown`, never "valid".
pub fn check_revocation(
    tokens: &[DelegationToken],
    decisions: &[AuthorizationDecision],
    revocations: &[RevocationRecord],
) -> Result<RevocationStatus, SignetError> {
    for rec in revocations {
        let issuer_pubkey = match rec.artifact_type {
            ArtifactType::DelegationToken => tokens
                .iter()
                .find(|t| t.id == rec.artifact_id)
                .map(|t| t.delegator.pubkey.clone()),
            ArtifactType::AuthorizationDecision => decisions
                .iter()
                .find(|d| d.decision_id == rec.artifact_id)
                .map(|d| d.authority_pubkey.clone()),
        };
        let Some(issuer) = issuer_pubkey else {
            continue; // record for an artifact not under verification
        };
        let issuer_vk = parse_verifying_key(&issuer).map_err(|e| {
            invalid_record(format!(
                "artifact '{}' has an unparseable issuer pubkey: {e}",
                rec.artifact_id
            ))
        })?;
        verify_revocation_record(rec, &issuer_vk)?;
        return Ok(RevocationStatus::Revoked {
            at: rec.revoked_at.clone(),
            by: rec.revoked_by.clone(),
        });
    }
    Ok(RevocationStatus::Unknown)
}

// ─── Local storage (single-host pilot grade) ────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
pub mod fs_ops {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    pub fn revocations_path(dir: &Path) -> PathBuf {
        dir.join("revocations.jsonl")
    }

    /// Append a record atomically: rewrite via temp file + rename, so a
    /// crashed append cannot truncate prior records.
    pub fn append_revocation(dir: &Path, record: &RevocationRecord) -> Result<(), SignetError> {
        let path = revocations_path(dir);
        let mut existing = fs::read_to_string(&path).unwrap_or_default();
        let line = serde_json::to_string(record)?;
        existing.push_str(&line);
        existing.push('\n');

        let tmp = dir.join("revocations.jsonl.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(existing.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Parse a JSONL file into records. Line numbers are 1-based; malformed
    /// lines are reported individually (never silently dropped).
    pub type DetailedRecords = Vec<(usize, Result<RevocationRecord, String>)>;

    pub fn load_revocations_detailed(path: &Path) -> Result<DetailedRecords, SignetError> {
        let content = fs::read_to_string(path).map_err(SignetError::IoError)?;
        Ok(content
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(i, line)| {
                (
                    i + 1,
                    serde_json::from_str(line)
                        .map_err(|e| format!("line {}: invalid JSON: {e}", i + 1)),
                )
            })
            .collect())
    }

    /// Load all well-formed records; hard-error listing the first bad line.
    pub fn load_revocations(path: &Path) -> Result<Vec<RevocationRecord>, SignetError> {
        let detailed = load_revocations_detailed(path)?;
        let mut records = Vec::with_capacity(detailed.len());
        for (_line, res) in detailed {
            records.push(res.map_err(|e| SignetError::CorruptedRecord(format!("{path:?}: {e}")))?);
        }
        Ok(records)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint::Constraint;

    pub(crate) fn test_token() -> (SigningKey, DelegationToken) {
        let (issuer_key, _) = crate::identity::generate_keypair();
        let (delegate_key, _) = crate::identity::generate_keypair();
        let token = crate::sign_delegation::sign_delegation_with_principals(
            &issuer_key,
            "alice",
            Some("user://prismer/alice"),
            &delegate_key.verifying_key(),
            "deploy-bot",
            Some("agent://prismer/deploy-bot"),
            &crate::delegation::Scope {
                tools: vec!["*".into()],
                targets: vec!["*".into()],
                max_depth: 0,
                expires: None,
                constraints: None,
            },
            None,
        )
        .unwrap();
        (issuer_key, token)
    }

    fn test_decision() -> (SigningKey, AuthorizationDecision) {
        let (authority_key, _) = crate::identity::generate_keypair();
        let action = crate::receipt::Action {
            tool: "payment".into(),
            params: serde_json::json!({"amount": 5}),
            params_hash: String::new(),
            target: "mcp://stripe".into(),
            transport: "stdio".into(),
            session: None,
            call_id: None,
            response_hash: None,
            trace_id: None,
            parent_receipt_id: None,
        };
        let intent = crate::authorization::CanonicalIntent::from_action(&action).unwrap();
        let decision = crate::authorization::authorize(
            &authority_key,
            "agent://prismer/security",
            "agent://prismer/deploy-bot",
            &intent,
            crate::authorization::DecisionType::Allow,
            crate::authorization::DecisionBasis::Policy {
                policy_hash: "sha256:abc".into(),
                policy_name: "p".into(),
                matched_rules: vec![],
                reason: String::new(),
            },
            vec![Constraint::CallCount { max_calls: 1 }],
            vec![],
            None,
            None,
        )
        .unwrap();
        (authority_key, decision)
    }

    #[test]
    fn test_revoke_token_roundtrip_and_status() {
        let (issuer_key, token) = test_token();
        let record = sign_revocation(
            &issuer_key,
            ArtifactType::DelegationToken,
            &token.id,
            "user://prismer/alice",
            "compromised",
        )
        .unwrap();

        let revoked_at = record.revoked_at.clone();
        assert_eq!(
            check_revocation(std::slice::from_ref(&token), &[], &[record]).unwrap(),
            RevocationStatus::Revoked {
                at: revoked_at,
                by: "user://prismer/alice".to_string(),
            }
        );
        // No records → Unknown, never "valid"
        assert_eq!(
            check_revocation(&[token], &[], &[]).unwrap(),
            RevocationStatus::Unknown
        );
    }

    #[test]
    fn test_revoke_decision_status() {
        let (authority_key, decision) = test_decision();
        let record = sign_revocation(
            &authority_key,
            ArtifactType::AuthorizationDecision,
            &decision.decision_id,
            "agent://prismer/security",
            "changed my mind",
        )
        .unwrap();
        let revoked_at = record.revoked_at.clone();
        assert_eq!(
            check_revocation(&[], &[decision], &[record]).unwrap(),
            RevocationStatus::Revoked {
                at: revoked_at,
                by: "agent://prismer/security".to_string(),
            }
        );
    }

    #[test]
    fn test_non_issuer_cannot_revoke() {
        let (_, token) = test_token();
        let (wrong_key, _) = crate::identity::generate_keypair();
        let record = sign_revocation(
            &wrong_key,
            ArtifactType::DelegationToken,
            &token.id,
            "user://evil/mallory",
            "forged",
        )
        .unwrap();
        // Signature decodes but does not verify against the delegator → hard error.
        let err = check_revocation(&[token], &[], &[record]).unwrap_err();
        assert!(err.to_string().contains("malformed revocation record"));
    }

    #[test]
    fn test_record_for_unknown_artifact_ignored() {
        let (issuer_key, token) = test_token();
        let record = sign_revocation(
            &issuer_key,
            ArtifactType::DelegationToken,
            "del_does_not_exist",
            "user://prismer/alice",
            "",
        )
        .unwrap();
        assert_eq!(
            check_revocation(&[token], &[], &[record]).unwrap(),
            RevocationStatus::Unknown
        );
    }

    #[test]
    fn test_tampered_record_rejected() {
        let (issuer_key, token) = test_token();
        let mut record = sign_revocation(
            &issuer_key,
            ArtifactType::DelegationToken,
            &token.id,
            "user://prismer/alice",
            "original reason",
        )
        .unwrap();
        record.reason = "rewritten".into();
        assert!(check_revocation(&[token], &[], &[record]).is_err());
    }

    #[test]
    fn test_sign_revocation_validates_inputs() {
        let (issuer_key, _) = crate::identity::generate_keypair();
        assert!(sign_revocation(
            &issuer_key,
            ArtifactType::DelegationToken,
            "del_x",
            "not-a-principal",
            ""
        )
        .is_err());
        assert!(sign_revocation(
            &issuer_key,
            ArtifactType::DelegationToken,
            "",
            "user://prismer/alice",
            ""
        )
        .is_err());
    }

    #[test]
    fn test_serde_field_names() {
        let json = r#"{"v":1,"artifact_type":"authorization_decision","artifact_id":"dec_1","revoked_by":"agent://prismer/security","revoked_at":"2026-09-20T00:00:00.000Z","reason":"x","nonce":"rnd_1","sig":"ed25519:AA=="}"#;
        let rec: RevocationRecord = serde_json::from_str(json).unwrap();
        assert_eq!(rec.artifact_type, ArtifactType::AuthorizationDecision);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod fs_tests {
    use super::tests::test_token;
    use super::*;

    #[test]
    fn test_append_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (issuer_key, token) = test_token();
        let record = sign_revocation(
            &issuer_key,
            ArtifactType::DelegationToken,
            &token.id,
            "user://prismer/alice",
            "test",
        )
        .unwrap();
        fs_ops::append_revocation(dir.path(), &record).unwrap();
        let loaded = fs_ops::load_revocations(&fs_ops::revocations_path(dir.path())).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].artifact_id, token.id);

        // Second append preserves the first (atomic rewrite, not truncate).
        let record2 = sign_revocation(
            &issuer_key,
            ArtifactType::DelegationToken,
            "del_other",
            "user://prismer/alice",
            "",
        )
        .unwrap();
        fs_ops::append_revocation(dir.path(), &record2).unwrap();
        let loaded = fs_ops::load_revocations(&fs_ops::revocations_path(dir.path())).unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_load_corrupt_line_reports_line_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = fs_ops::revocations_path(dir.path());
        let good = r#"{"v":1,"artifact_type":"delegation_token","artifact_id":"del_1","revoked_by":"user://prismer/alice","revoked_at":"2026-09-20T00:00:00.000Z","reason":"","nonce":"rnd_1","sig":"ed25519:AA=="}"#;
        std::fs::write(&path, format!("{good}\nnot json\n")).unwrap();
        let err = fs_ops::load_revocations(&path).unwrap_err();
        assert!(err.to_string().contains("line 2"));
        // Detailed view keeps the good line.
        let detailed = fs_ops::load_revocations_detailed(&path).unwrap();
        assert_eq!(detailed.len(), 2);
        assert!(detailed[0].1.is_ok());
        assert!(detailed[1].1.is_err());
    }
}
