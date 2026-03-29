use std::io::IsTerminal;
use std::process;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

mod cmd_identity;
mod cmd_sign;
mod cmd_verify;

#[derive(Parser)]
#[command(name = "signet", about = "Cryptographic action receipts for AI agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage agent identities (Ed25519 keypairs)
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Sign an action and produce a receipt
    Sign(cmd_sign::SignArgs),
    /// Verify an action receipt
    Verify(cmd_verify::VerifyArgs),
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new agent identity
    Generate(cmd_identity::GenerateArgs),
    /// List all identities
    List,
    /// Export a public key
    Export(cmd_identity::ExportArgs),
}

pub fn get_passphrase(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var("SIGNET_PASSPHRASE") {
        if p.is_empty() {
            bail!("SIGNET_PASSPHRASE is set but empty");
        }
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {
        bail!("no TTY and SIGNET_PASSPHRASE not set — cannot read passphrase");
    }
    let p = rpassword::prompt_password(prompt)?;
    if p.is_empty() {
        bail!("passphrase cannot be empty");
    }
    Ok(p)
}

pub fn get_passphrase_confirm() -> Result<String> {
    let p1 = get_passphrase("Enter passphrase: ")?;
    let p2 = get_passphrase("Confirm passphrase: ")?;
    if p1 != p2 {
        bail!("passphrases do not match");
    }
    Ok(p1)
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Identity { action } => match action {
            IdentityAction::Generate(args) => cmd_identity::generate(args)?,
            IdentityAction::List => cmd_identity::list()?,
            IdentityAction::Export(args) => cmd_identity::export(args)?,
        },
        Commands::Sign(args) => cmd_sign::sign(args)?,
        Commands::Verify(args) => cmd_verify::verify(args)?,
    }
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("signature verification failed") {
                eprintln!("Invalid: {e}");
                process::exit(1);
            } else {
                eprintln!("Error: {e}");
                process::exit(3);
            }
        }
    }
}
