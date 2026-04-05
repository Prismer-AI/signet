use std::fs;

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::Args;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to receipt JSON file
    pub receipt: Option<String>,

    /// Public key name or file path
    #[arg(long)]
    pub pubkey: Option<String>,

    /// Verify audit log hash chain integrity
    #[arg(long)]
    pub chain: bool,
}

pub fn verify(args: VerifyArgs) -> Result<()> {
    if args.chain {
        if args.receipt.is_some() || args.pubkey.is_some() {
            bail!("--chain cannot be used with receipt or --pubkey");
        }
        return verify_chain();
    }

    // Receipt verification mode
    let receipt_path = args
        .receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("receipt file path required (or use --chain)"))?;
    let pubkey = args
        .pubkey
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--pubkey required for receipt verification"))?;

    let receipt_str = fs::read_to_string(receipt_path)
        .map_err(|e| anyhow::anyhow!("failed to read receipt '{receipt_path}': {e}"))?;

    // Parse as generic JSON first to peek at version and extract display fields.
    let raw: serde_json::Value = serde_json::from_str(&receipt_str)
        .map_err(|e| anyhow::anyhow!("failed to parse receipt JSON: {e}"))?;
    let version = raw.get("v").and_then(|v| v.as_u64()).unwrap_or(1);

    let vk = if pubkey.contains('/') || pubkey.ends_with(".pub") {
        let content = fs::read_to_string(pubkey)
            .map_err(|e| anyhow::anyhow!("failed to read pubkey file '{pubkey}': {e}"))?;
        let pub_file: signet_core::keystore::PubKeyFile = serde_json::from_str(&content)?;
        let b64 = pub_file
            .pubkey
            .strip_prefix("ed25519:")
            .unwrap_or(&pub_file.pubkey);
        let bytes = BASE64.decode(b64)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("pubkey is not 32 bytes"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&arr)?
    } else {
        let dir = signet_core::default_signet_dir();
        signet_core::load_verifying_key(&dir, pubkey)?
    };

    match signet_core::verify_any(&receipt_str, &vk) {
        Ok(()) => {
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
                println!(
                    "Valid: \"{signer_name}\" dispatched \"{tool}\" → response at {ts_response}"
                );
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
