use std::fs;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Args;

#[derive(Args)]
pub struct VerifyArgs {
    pub receipt: String,
    #[arg(long)]
    pub pubkey: String,
}

pub fn verify(args: VerifyArgs) -> Result<()> {
    let receipt_str = fs::read_to_string(&args.receipt)
        .map_err(|e| anyhow::anyhow!("failed to read receipt '{}': {e}", args.receipt))?;
    let receipt: signet_core::Receipt = serde_json::from_str(&receipt_str)?;

    let vk = if args.pubkey.contains('/') || args.pubkey.ends_with(".pub") {
        let content = fs::read_to_string(&args.pubkey)
            .map_err(|e| anyhow::anyhow!("failed to read pubkey file '{}': {e}", args.pubkey))?;
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
        signet_core::load_verifying_key(&dir, &args.pubkey)?
    };

    match signet_core::verify(&receipt, &vk) {
        Ok(()) => {
            println!(
                "Valid: \"{}\" signed \"{}\" at {}",
                receipt.signer.name, receipt.action.tool, receipt.ts
            );
        }
        Err(signet_core::SignetError::SignatureMismatch) => {
            anyhow::bail!("signature verification failed");
        }
        Err(e) => {
            anyhow::bail!("verification error: {e}");
        }
    }
    Ok(())
}
