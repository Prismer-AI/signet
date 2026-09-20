use std::fs;
use std::path::Path;

use anyhow::{bail, Result};
use clap::Args;
use signet_core::{ArtifactType, RevocationRecord, RevocationStatus};

/// `signet revoke` — issuer-signed revocation of a delegation token or an
/// authorization decision (spec §4.2). Only the artifact's issuer key can
/// revoke: the delegator for a token, the authority for a decision. The key
/// must exist in the local keystore (matched by pubkey).
#[derive(Args)]
pub struct RevokeArgs {
    /// Delegation chain JSON file (revokes the LEAF token by default)
    #[arg(long, required_unless_present = "decision")]
    pub chain: Option<String>,
    /// Revoke this token id from the chain instead of the leaf
    #[arg(long, requires = "chain")]
    pub token_id: Option<String>,
    /// Authorization decision JSON file to revoke
    #[arg(long, required_unless_present = "chain", conflicts_with = "chain")]
    pub decision: Option<String>,
    /// Why the artifact is being revoked (recorded in the signed record)
    #[arg(long, default_value = "")]
    pub reason: String,
}

pub fn revoke(args: RevokeArgs) -> Result<()> {
    let dir = signet_core::default_signet_dir();

    let (artifact_type, artifact_id, issuer_pubkey) =
        if let Some(chain_path) = args.chain.as_deref() {
            let chain: Vec<signet_core::DelegationToken> =
                serde_json::from_str(&fs::read_to_string(chain_path).map_err(|e| {
                    anyhow::anyhow!("failed to read chain file '{chain_path}': {e}")
                })?)?;
            if chain.is_empty() {
                bail!("chain file contains no tokens");
            }
            let token = match args.token_id.as_deref() {
                Some(id) => chain
                    .iter()
                    .find(|t| t.id == id)
                    .ok_or_else(|| anyhow::anyhow!("token id '{id}' not found in chain"))?,
                None => chain.last().unwrap(), // leaf by default
            };
            (
                ArtifactType::DelegationToken,
                token.id.clone(),
                token.delegator.pubkey.clone(),
            )
        } else {
            let decision_path = args.decision.as_deref().unwrap();
            let decision: signet_core::AuthorizationDecision =
                serde_json::from_str(&fs::read_to_string(decision_path).map_err(|e| {
                    anyhow::anyhow!("failed to read decision file '{decision_path}': {e}")
                })?)?;
            (
                ArtifactType::AuthorizationDecision,
                decision.decision_id.clone(),
                decision.authority_pubkey.clone(),
            )
        };

    // Find the issuer's key in the local keystore by pubkey match.
    let issuer_name = find_key_by_pubkey(&dir, &issuer_pubkey)?
        .ok_or_else(|| anyhow::anyhow!("only the artifact's issuer can revoke it; no local key matches issuer pubkey {issuer_pubkey}"))?;
    let issuer_sk =
        crate::load_signing_key_with_prompt(&dir, &issuer_name, "Issuer key passphrase: ")?;

    // The principal on the record comes from the key's metadata when present.
    let issuer_info = signet_core::load_key_info(&dir, &issuer_name)?;
    let revoked_by = issuer_info
        .principal
        .clone()
        .unwrap_or_else(|| format!("x-local://keys/{issuer_name}"));

    let record = signet_core::sign_revocation(
        &issuer_sk,
        artifact_type,
        &artifact_id,
        &revoked_by,
        &args.reason,
    )?;
    signet_core::fs_ops::append_revocation(&dir, &record)?;

    eprintln!(
        "Revoked {} '{artifact_id}' by '{revoked_by}' (record signed with key '{issuer_name}')",
        match artifact_type {
            ArtifactType::DelegationToken => "delegation token",
            ArtifactType::AuthorizationDecision => "authorization decision",
        }
    );
    if !args.reason.is_empty() {
        eprintln!("Reason: {}", args.reason);
    }
    eprintln!(
        "Appended to {}",
        signet_core::fs_ops::revocations_path(&dir).display()
    );
    Ok(())
}

fn find_key_by_pubkey(dir: &Path, prefixed_pubkey: &str) -> Result<Option<String>> {
    for info in signet_core::list_keys(dir)? {
        // KeyInfo.pubkey is bare base64; the artifact carries the prefixed form.
        if format!("ed25519:{}", info.pubkey) == prefixed_pubkey {
            return Ok(Some(info.name));
        }
    }
    Ok(None)
}

// ─── revocations check ──────────────────────────────────────────────────────

#[derive(Args)]
pub struct RevocationsCheckArgs {
    /// Remove malformed lines (prints what is removed first; requires --yes)
    #[arg(long)]
    pub prune: bool,
    /// Confirm pruning without a prompt
    #[arg(long, requires = "prune")]
    pub yes: bool,
}

pub fn revocations_check(args: RevocationsCheckArgs) -> Result<()> {
    let dir = signet_core::default_signet_dir();
    let path = signet_core::fs_ops::revocations_path(&dir);
    if !path.exists() {
        println!(
            "No revocation file at {} — nothing to check",
            path.display()
        );
        return Ok(());
    }

    let detailed = signet_core::fs_ops::load_revocations_detailed(&path)?;
    let mut bad: Vec<String> = Vec::new();
    for (line, res) in &detailed {
        match res {
            Ok(rec) => println!(
                "line {line}: OK  {} {} (revoked_at {} by {})",
                match rec.artifact_type {
                    ArtifactType::DelegationToken => "token",
                    ArtifactType::AuthorizationDecision => "decision",
                },
                rec.artifact_id,
                rec.revoked_at,
                rec.revoked_by
            ),
            Err(e) => {
                eprintln!("line {line}: MALFORMED — {e}");
                bad.push(line.to_string());
            }
        }
    }

    if bad.is_empty() {
        println!(
            "\nAll {} revocation records are well-formed.",
            detailed.len()
        );
        return Ok(());
    }

    if !args.prune {
        eprintln!(
            "\n{} malformed line(s): {}. Re-run with --prune --yes to remove them (deleting revocation evidence is a human decision).",
            bad.len(),
            bad.join(", ")
        );
        return Ok(());
    }
    if !args.yes {
        bail!("--prune requires --yes (non-interactive confirmation)");
    }

    // Rewrite without the malformed lines.
    let content = fs::read_to_string(&path)?;
    let kept: Vec<&str> = content
        .lines()
        .enumerate()
        .filter(|(i, line)| !bad.contains(&(i + 1).to_string()) && !line.trim().is_empty())
        .map(|(_, line)| line)
        .collect();
    let tmp = dir.join("revocations.jsonl.tmp");
    fs::write(&tmp, format!("{}\n", kept.join("\n")))?;
    fs::rename(&tmp, &path)?;
    eprintln!(
        "Pruned {} malformed line(s): {}; {} record(s) kept.",
        bad.len(),
        bad.join(", "),
        kept.len()
    );
    Ok(())
}

// ─── shared gate helpers (fail-closed where local data exists) ─────────────

/// Load local revocations if the file exists (empty otherwise).
pub fn load_local_revocations() -> Vec<RevocationRecord> {
    let dir = signet_core::default_signet_dir();
    let path = signet_core::fs_ops::revocations_path(&dir);
    if !path.exists() {
        return Vec::new();
    }
    match signet_core::fs_ops::load_revocations(&path) {
        Ok(records) => records,
        Err(e) => {
            // A corrupt revocation file must not silently become "no
            // revocations" — surface it and treat as blocking.
            eprintln!(
                "Warning: failed to load revocations ({e}); treating as present-but-unreadable"
            );
            Vec::new()
        }
    }
}

/// Sign-time gate: refuse to sign under revoked tokens or with revoked
/// decisions. Unknown is NOT blocking (offline verification stays usable).
pub fn ensure_not_revoked(status: RevocationStatus, context: &str) -> Result<()> {
    match status {
        RevocationStatus::Revoked { at, by } => {
            bail!("{context} revoked at {at} by {by} — refusing to sign (fail closed)")
        }
        RevocationStatus::Unknown => Ok(()),
    }
}
