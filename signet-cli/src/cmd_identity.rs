use anyhow::Result;
use clap::Args;
use signet_core::{default_signet_dir, keystore::KdfParams};

#[derive(Args)]
pub struct GenerateArgs {
    #[arg(long)]
    pub name: String,

    #[arg(long, default_value = "")]
    pub owner: String,

    #[arg(long)]
    pub unencrypted: bool,
}

#[derive(Args)]
pub struct ExportArgs {
    #[arg(long)]
    pub name: String,
}

pub fn generate(args: GenerateArgs) -> Result<()> {
    let dir = default_signet_dir();
    let passphrase = if args.unencrypted {
        None
    } else {
        Some(super::get_passphrase_confirm()?)
    };
    let owner = if args.owner.is_empty() {
        None
    } else {
        Some(args.owner.as_str())
    };
    let info = signet_core::generate_and_save(
        &dir,
        &args.name,
        owner,
        passphrase.as_deref(),
        Some(KdfParams::new()),
    )?;
    eprintln!(
        "Identity '{}' created at {}/keys/",
        info.name,
        dir.display()
    );
    println!("{}", info.pubkey);
    Ok(())
}

pub fn list() -> Result<()> {
    let dir = default_signet_dir();
    let keys = signet_core::list_keys(&dir)?;
    if keys.is_empty() {
        println!("No keys found in {}/keys/", dir.display());
        return Ok(());
    }
    println!("{:<20} {:<20} CREATED", "NAME", "OWNER");
    println!("{}", "-".repeat(60));
    for key in &keys {
        println!(
            "{:<20} {:<20} {}",
            key.name,
            key.owner.as_deref().unwrap_or(""),
            key.created_at
        );
    }
    Ok(())
}

pub fn export(args: ExportArgs) -> Result<()> {
    let dir = default_signet_dir();
    let pub_file = signet_core::export_public_key(&dir, &args.name)?;
    let json = serde_json::to_string_pretty(&pub_file)?;
    println!("{json}");
    Ok(())
}
