use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Subcommand, ValueEnum};

#[derive(Subcommand)]
pub enum TrustAction {
    /// Inspect a trust bundle and show summary plus entries.
    Inspect(InspectArgs),
    /// List trust bundle entries, optionally filtered by section or active status.
    List(ListArgs),
    /// Disable one trust entry in-place or write to a new output path.
    Disable(UpdateArgs),
    /// Revoke one trust entry in-place or write to a new output path.
    Revoke(UpdateArgs),
    /// Rotate one trust entry by adding a new active key and optionally preserving overlap.
    Rotate(RotateArgs),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum TrustSection {
    Roots,
    Agents,
    Servers,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Trust bundle file (YAML or JSON)
    pub path: String,
}

#[derive(Args)]
pub struct ListArgs {
    /// Trust bundle file (YAML or JSON)
    pub path: String,
    /// Restrict output to one section.
    #[arg(long, value_enum)]
    pub section: Option<TrustSection>,
    /// Show only entries that are currently active.
    #[arg(long)]
    pub active_only: bool,
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Trust bundle file (YAML or JSON)
    pub path: String,
    /// Section to update.
    #[arg(long, value_enum)]
    pub section: TrustSection,
    /// Entry ID to update.
    #[arg(long)]
    pub id: String,
    /// Optional explicit timestamp. Defaults to now.
    #[arg(long)]
    pub at: Option<String>,
    /// Write updated bundle to this path instead of replacing the input file.
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Args)]
pub struct RotateArgs {
    /// Trust bundle file (YAML or JSON)
    pub path: String,
    /// Section to update.
    #[arg(long, value_enum)]
    pub section: TrustSection,
    /// Existing entry ID to rotate from.
    #[arg(long)]
    pub id: String,
    /// New entry ID.
    #[arg(long)]
    pub new_id: String,
    /// New public key in ed25519:<base64> format.
    #[arg(long)]
    pub new_pubkey: String,
    /// Optional replacement display name. Defaults to the old entry name.
    #[arg(long)]
    pub new_name: Option<String>,
    /// Optional replacement owner. Defaults to the old entry owner.
    #[arg(long)]
    pub new_owner: Option<String>,
    /// Keep the old key active until this timestamp, then let it expire.
    #[arg(long)]
    pub overlap_until: Option<String>,
    /// Optional explicit timestamp for the new entry created_at and disable/revoke marker.
    #[arg(long)]
    pub at: Option<String>,
    /// Write updated bundle to this path instead of replacing the input file.
    #[arg(long)]
    pub output: Option<String>,
}

pub fn run(action: TrustAction) -> Result<()> {
    match action {
        TrustAction::Inspect(args) => inspect(args),
        TrustAction::List(args) => list(args),
        TrustAction::Disable(args) => disable(args),
        TrustAction::Revoke(args) => revoke(args),
        TrustAction::Rotate(args) => rotate(args),
    }
}

fn inspect(args: InspectArgs) -> Result<()> {
    let bundle = signet_core::load_trust_bundle(Path::new(&args.path))?;
    let now = Utc::now();

    println!("Bundle: {}", bundle.bundle_id);
    println!("Org: {}", bundle.org);
    println!("Env: {}", bundle.env);
    println!("Generated: {}", bundle.generated_at);
    if let Some(description) = &bundle.description {
        println!("Description: {description}");
    }
    println!();

    print_section_summary("roots", &bundle.roots, now);
    print_section_summary("agents", &bundle.agents, now);
    print_section_summary("servers", &bundle.servers, now);
    println!();
    print_entries(&bundle, None, false, now);
    Ok(())
}

fn list(args: ListArgs) -> Result<()> {
    let bundle = signet_core::load_trust_bundle(Path::new(&args.path))?;
    let now = Utc::now();
    print_entries(&bundle, args.section, args.active_only, now);
    Ok(())
}

fn disable(args: UpdateArgs) -> Result<()> {
    let path = Path::new(&args.path);
    let output_path = output_path(path, args.output.as_deref());
    let mut bundle = signet_core::load_trust_bundle(path)?;
    let at = timestamp_or_now(args.at.as_deref())?;
    let entry = find_entry_mut(&mut bundle, args.section, &args.id)?;

    entry.status = signet_core::TrustKeyStatus::Disabled;
    entry.disabled_at = Some(at.clone());
    entry.revoked_at = None;
    bundle.generated_at = at.clone();

    signet_core::save_trust_bundle(&output_path, &bundle)?;
    eprintln!(
        "Disabled {} entry '{}' in {}",
        section_name(args.section),
        args.id,
        output_path.display()
    );
    Ok(())
}

fn revoke(args: UpdateArgs) -> Result<()> {
    let path = Path::new(&args.path);
    let output_path = output_path(path, args.output.as_deref());
    let mut bundle = signet_core::load_trust_bundle(path)?;
    let at = timestamp_or_now(args.at.as_deref())?;
    let entry = find_entry_mut(&mut bundle, args.section, &args.id)?;

    entry.status = signet_core::TrustKeyStatus::Revoked;
    entry.revoked_at = Some(at.clone());
    entry.disabled_at = None;
    bundle.generated_at = at.clone();

    signet_core::save_trust_bundle(&output_path, &bundle)?;
    eprintln!(
        "Revoked {} entry '{}' in {}",
        section_name(args.section),
        args.id,
        output_path.display()
    );
    Ok(())
}

fn rotate(args: RotateArgs) -> Result<()> {
    let path = Path::new(&args.path);
    let output_path = output_path(path, args.output.as_deref());
    let mut bundle = signet_core::load_trust_bundle(path)?;
    let at = timestamp_or_now(args.at.as_deref())?;
    let at_dt = parse_utc_timestamp(&at)?;

    {
        let entries = section_entries(&bundle, args.section);
        if entries.iter().any(|entry| entry.id == args.new_id) {
            bail!(
                "{} already contains entry id '{}'",
                section_name(args.section),
                args.new_id
            );
        }
        if entries.iter().any(|entry| entry.pubkey == args.new_pubkey) {
            bail!(
                "{} already contains pubkey '{}'",
                section_name(args.section),
                args.new_pubkey
            );
        }
    }

    let old_entry = find_entry_mut(&mut bundle, args.section, &args.id)?;
    if old_entry.status != signet_core::TrustKeyStatus::Active {
        bail!(
            "entry '{}' is not active and cannot be rotated (status: {:?})",
            args.id,
            old_entry.status
        );
    }

    let new_entry = signet_core::TrustKeyEntry {
        id: args.new_id.clone(),
        name: args
            .new_name
            .clone()
            .unwrap_or_else(|| old_entry.name.clone()),
        owner: args
            .new_owner
            .clone()
            .unwrap_or_else(|| old_entry.owner.clone()),
        pubkey: args.new_pubkey.clone(),
        status: signet_core::TrustKeyStatus::Active,
        created_at: at.clone(),
        expires_at: None,
        disabled_at: None,
        revoked_at: None,
        comment: Some(format!("rotated from {}", old_entry.id)),
    };

    if let Some(overlap_until) = args.overlap_until.as_deref() {
        let overlap_until = timestamp_or_now(Some(overlap_until))?;
        let overlap_until_dt = parse_utc_timestamp(&overlap_until)?;
        if overlap_until_dt <= at_dt {
            bail!(
                "overlap_until must be later than the rotation timestamp '{}'",
                at
            );
        }
        old_entry.expires_at = Some(overlap_until);
        old_entry.disabled_at = None;
        old_entry.revoked_at = None;
    } else {
        old_entry.status = signet_core::TrustKeyStatus::Disabled;
        old_entry.disabled_at = Some(at.clone());
        old_entry.revoked_at = None;
    }

    bundle.generated_at = at.clone();
    section_entries_mut(&mut bundle, args.section).push(new_entry);
    signet_core::save_trust_bundle(&output_path, &bundle)?;
    eprintln!(
        "Rotated {} entry '{}' -> '{}' in {}",
        section_name(args.section),
        args.id,
        args.new_id,
        output_path.display()
    );
    Ok(())
}

fn print_section_summary(
    name: &str,
    entries: &[signet_core::TrustKeyEntry],
    now: chrono::DateTime<Utc>,
) {
    let total = entries.len();
    let active = entries
        .iter()
        .filter(|entry| entry.is_active_at(now))
        .count();
    let disabled = entries
        .iter()
        .filter(|entry| entry.status == signet_core::TrustKeyStatus::Disabled)
        .count();
    let revoked = entries
        .iter()
        .filter(|entry| entry.status == signet_core::TrustKeyStatus::Revoked)
        .count();
    let expired = entries
        .iter()
        .filter(|entry| {
            entry.status == signet_core::TrustKeyStatus::Active && !entry.is_active_at(now)
        })
        .count();

    println!(
        "{}: total={} active={} disabled={} revoked={} expired={}",
        name, total, active, disabled, revoked, expired
    );
}

fn print_entries(
    bundle: &signet_core::TrustBundle,
    section: Option<TrustSection>,
    active_only: bool,
    now: chrono::DateTime<Utc>,
) {
    println!(
        "{:<8} {:<20} {:<20} {:<12} {:<20} PUBKEY",
        "SECTION", "ID", "NAME", "STATUS", "OWNER"
    );
    println!("{}", "-".repeat(110));

    for current in sections_to_print(section) {
        for entry in section_entries(bundle, current) {
            let status = entry_status_label(entry, now);
            if active_only && status != "active" {
                continue;
            }
            println!(
                "{:<8} {:<20} {:<20} {:<12} {:<20} {}",
                section_name(current),
                entry.id,
                entry.name,
                status,
                entry.owner,
                entry.pubkey
            );
        }
    }
}

fn entry_status_label(
    entry: &signet_core::TrustKeyEntry,
    now: chrono::DateTime<Utc>,
) -> &'static str {
    match entry.status {
        signet_core::TrustKeyStatus::Active if entry.is_active_at(now) => "active",
        signet_core::TrustKeyStatus::Active => "expired",
        signet_core::TrustKeyStatus::Disabled => "disabled",
        signet_core::TrustKeyStatus::Revoked => "revoked",
    }
}

fn sections_to_print(section: Option<TrustSection>) -> Vec<TrustSection> {
    match section {
        Some(section) => vec![section],
        None => vec![
            TrustSection::Roots,
            TrustSection::Agents,
            TrustSection::Servers,
        ],
    }
}

fn find_entry_mut<'a>(
    bundle: &'a mut signet_core::TrustBundle,
    section: TrustSection,
    id: &str,
) -> Result<&'a mut signet_core::TrustKeyEntry> {
    section_entries_mut(bundle, section)
        .iter_mut()
        .find(|entry| entry.id == id)
        .ok_or_else(|| anyhow!("{} entry '{}' not found", section_name(section), id))
}

fn section_entries(
    bundle: &signet_core::TrustBundle,
    section: TrustSection,
) -> &[signet_core::TrustKeyEntry] {
    match section {
        TrustSection::Roots => &bundle.roots,
        TrustSection::Agents => &bundle.agents,
        TrustSection::Servers => &bundle.servers,
    }
}

fn section_entries_mut(
    bundle: &mut signet_core::TrustBundle,
    section: TrustSection,
) -> &mut Vec<signet_core::TrustKeyEntry> {
    match section {
        TrustSection::Roots => &mut bundle.roots,
        TrustSection::Agents => &mut bundle.agents,
        TrustSection::Servers => &mut bundle.servers,
    }
}

fn section_name(section: TrustSection) -> &'static str {
    match section {
        TrustSection::Roots => "roots",
        TrustSection::Agents => "agents",
        TrustSection::Servers => "servers",
    }
}

fn timestamp_or_now(value: Option<&str>) -> Result<String> {
    match value {
        Some(value) => Ok(parse_utc_timestamp(value)?.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
        None => Ok(Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true)),
    }
}

fn parse_utc_timestamp(value: &str) -> Result<chrono::DateTime<Utc>> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|e| anyhow!("invalid timestamp '{}': {}", value, e))?;

    if parsed.offset().local_minus_utc() != 0 {
        bail!("timestamp '{}' must use UTC ('Z' or '+00:00')", value);
    }

    Ok(parsed.with_timezone(&Utc))
}

fn output_path(input: &Path, output: Option<&str>) -> PathBuf {
    output
        .map(PathBuf::from)
        .unwrap_or_else(|| input.to_path_buf())
}
