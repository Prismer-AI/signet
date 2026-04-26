use std::fs;

use anyhow::{bail, Result};
use clap::Args;

use crate::trust_helpers::{load_cli_trust_bundle, resolve_pubkey, LoadedTrustBundle};

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to receipt JSON file
    pub receipt: Option<String>,

    /// Public key name or file path
    #[arg(long)]
    pub pubkey: Option<String>,

    /// Trust bundle file (YAML or JSON) containing active trusted roots/agents/servers.
    #[arg(long)]
    pub trust_bundle: Option<String>,

    /// Verify audit log hash chain integrity
    #[arg(long)]
    pub chain: bool,
}

pub fn verify(args: VerifyArgs) -> Result<()> {
    if args.chain {
        if args.receipt.is_some() || args.pubkey.is_some() || args.trust_bundle.is_some() {
            bail!("--chain cannot be used with receipt, --pubkey, or --trust-bundle");
        }
        return verify_chain();
    }

    if args.pubkey.is_some() && args.trust_bundle.is_some() {
        bail!("--pubkey and --trust-bundle are mutually exclusive");
    }

    // Receipt verification mode
    let receipt_path = args
        .receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("receipt file path required (or use --chain)"))?;

    let receipt_str = fs::read_to_string(receipt_path)
        .map_err(|e| anyhow::anyhow!("failed to read receipt '{receipt_path}': {e}"))?;

    // Parse as generic JSON first to peek at version and extract display fields.
    let raw: serde_json::Value = serde_json::from_str(&receipt_str)
        .map_err(|e| anyhow::anyhow!("failed to parse receipt JSON: {e}"))?;
    let version = raw.get("v").and_then(|v| v.as_u64()).unwrap_or(1);

    if let Some(bundle_path) = args.trust_bundle.as_deref() {
        let trust_bundle = load_cli_trust_bundle(bundle_path)?;
        eprintln!("Using trust bundle {}", trust_bundle.describe());
        return verify_with_trust_bundle(&receipt_str, &raw, version, &trust_bundle);
    }

    let pubkey = args.pubkey.as_ref().ok_or_else(|| {
        anyhow::anyhow!("--pubkey or --trust-bundle required for receipt verification")
    })?;

    let vk = {
        let dir = signet_core::default_signet_dir();
        resolve_pubkey(&dir, pubkey)?
    };

    match signet_core::verify_any(&receipt_str, &vk) {
        Ok(()) => {
            print_valid_message(&raw, version);
        }
        Err(signet_core::SignetError::SignatureMismatch) => {
            bail!("signature verification failed");
        }
        Err(e) => {
            bail!("verification error: {e}");
        }
    }
    Ok(())
}

fn verify_chain() -> Result<()> {
    let dir = signet_core::default_signet_dir();
    eprintln!("Verifying chain integrity...");

    let status = signet_core::audit::verify_chain(&dir)?;

    if status.valid {
        println!("Chain intact: {} records verified", status.total_records);
    } else if let Some(bp) = status.break_point {
        eprintln!("Chain broken at {}:{}", bp.file, bp.line);
        eprintln!("  expected prev_hash: {}", bp.expected_hash);
        eprintln!("  actual prev_hash:   {}", bp.actual_hash);
        bail!("signature verification failed");
    }
    Ok(())
}

fn verify_with_trust_bundle(
    receipt_str: &str,
    raw: &serde_json::Value,
    version: u64,
    trust_bundle: &LoadedTrustBundle,
) -> Result<()> {
    match version {
        1 | 2 => {
            let signer_pubkey = raw
                .get("signer")
                .and_then(|s| s.get("pubkey"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing signer.pubkey"))?;
            let vk = trust_bundle
                .find_active_agent_key(signer_pubkey)?
                .ok_or_else(|| anyhow::anyhow!("untrusted signer pubkey: {signer_pubkey}"))?;

            match signet_core::verify_any(receipt_str, &vk) {
                Ok(()) => print_valid_message(raw, version),
                Err(signet_core::SignetError::SignatureMismatch) => {
                    bail!("signature verification failed")
                }
                Err(e) => bail!("verification error: {e}"),
            }
        }
        3 => {
            let bilateral: signet_core::BilateralReceipt = serde_json::from_str(receipt_str)
                .map_err(|e| anyhow::anyhow!("failed to parse v3 bilateral receipt: {e}"))?;
            let agent_vk = trust_bundle
                .find_active_agent_key(&bilateral.agent_receipt.signer.pubkey)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "untrusted agent pubkey: {}",
                        bilateral.agent_receipt.signer.pubkey
                    )
                })?;
            let server_vk = trust_bundle
                .find_active_server_key(&bilateral.server.pubkey)?
                .ok_or_else(|| {
                    anyhow::anyhow!("untrusted server pubkey: {}", bilateral.server.pubkey)
                })?;

            let opts = signet_core::BilateralVerifyOptions {
                trusted_agent_pubkey: Some(agent_vk),
                ..Default::default()
            };

            match signet_core::verify_bilateral_with_options_detailed(&bilateral, &server_vk, &opts)
            {
                Ok(signet_core::BilateralVerifyOutcome::AgentTrusted) => {
                    let signer_name = bilateral.agent_receipt.signer.name;
                    let tool = bilateral.agent_receipt.action.tool;
                    println!(
                        "Valid: bilateral receipt trusted for \"{signer_name}\" tool \"{tool}\""
                    );
                }
                Ok(signet_core::BilateralVerifyOutcome::AgentSelfConsistent) => bail!(
                    "bilateral receipt verified only for self-consistency, not trusted identity"
                ),
                Err(signet_core::SignetError::SignatureMismatch) => {
                    bail!("signature verification failed")
                }
                Err(e) => bail!("verification error: {e}"),
            }
        }
        4 => {
            let receipt: signet_core::Receipt = serde_json::from_str(receipt_str)
                .map_err(|e| anyhow::anyhow!("failed to parse v4 receipt: {e}"))?;
            if trust_bundle.active_root_pubkeys.is_empty() {
                bail!("trust bundle has no active roots for authorization verification");
            }

            let opts = signet_core::AuthorizedVerifyOptions {
                trusted_roots: trust_bundle.active_root_pubkeys.clone(),
                clock_skew_secs: 60,
                max_chain_depth: 16,
            };

            match signet_core::verify_authorized(&receipt, &opts) {
                Ok(_) => {
                    let signer_name = receipt.signer.name;
                    let tool = receipt.action.tool;
                    let ts = receipt.ts;
                    println!("Valid: authorized \"{signer_name}\" signed \"{tool}\" at {ts}");
                }
                Err(signet_core::SignetError::SignatureMismatch) => {
                    bail!("signature verification failed")
                }
                Err(e) => bail!("verification error: {e}"),
            }
        }
        _ => bail!("verification error: unsupported version: {version}"),
    }

    Ok(())
}

fn print_valid_message(raw: &serde_json::Value, version: u64) {
    if version == 2 {
        let signer_name = raw
            .get("signer")
            .and_then(|s| s.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let tool = raw
            .get("action")
            .and_then(|a| a.get("tool"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let ts_response = raw
            .get("ts_response")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        println!("Valid: \"{signer_name}\" dispatched \"{tool}\" → response at {ts_response}");
    } else {
        let signer_name = raw
            .get("signer")
            .and_then(|s| s.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let tool = raw
            .get("action")
            .and_then(|a| a.get("tool"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let ts = raw
            .get("ts")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        println!("Valid: \"{signer_name}\" signed \"{tool}\" at {ts}");
    }
}
