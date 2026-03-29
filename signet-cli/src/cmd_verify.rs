use std::fs;

use anyhow::{bail, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
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
    let receipt_path = args.receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("receipt file path required (or use --chain)"))?;
    let pubkey = args.pubkey
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--pubkey required for receipt verification"))?;

    let receipt_str = fs::read_to_string(receipt_path)
        .map_err(|e| anyhow::anyhow!("failed to read receipt '{receipt_path}': {e}"))?;
    let receipt: signet_core::Receipt = serde_json::from_str(&receipt_str)?;

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

    match signet_core::verify(&receipt, &vk) {
        Ok(()) => {
            println!(
                "Valid: \"{}\" signed \"{}\" at {}",
                receipt.signer.name, receipt.action.tool, receipt.ts
            );
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
