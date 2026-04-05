use anyhow::{Context, Result};
use clap::Subcommand;
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum ClaudeAction {
    /// Install Signet skill + hooks for Claude Code
    Install,
    /// Remove Signet skill from Claude Code
    Uninstall,
    /// Show recent signed tool calls
    Audit,
}

fn claude_skills_dir() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    Ok(home.join(".claude/skills/signet"))
}

fn signet_bin() -> Result<String> {
    let exe = std::env::current_exe().context("cannot determine signet binary path")?;
    exe.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("signet binary path is not valid UTF-8"))
}

pub fn run(action: ClaudeAction) -> Result<()> {
    match action {
        ClaudeAction::Install => install(),
        ClaudeAction::Uninstall => uninstall(),
        ClaudeAction::Audit => audit(),
    }
}

fn install() -> Result<()> {
    let skills_dir = claude_skills_dir()?;
    let bin_dir = skills_dir.join("bin");

    fs::create_dir_all(&bin_dir)
        .with_context(|| format!("failed to create {}", bin_dir.display()))?;

    // Generate identity if not exists
    let signet_dir = signet_core::default_signet_dir();
    let key_path = signet_dir.join("keys/claude-agent.key");
    if !key_path.exists() {
        eprintln!("Generating claude-agent identity (unencrypted for automated signing)...");
        eprintln!("  Key will be stored at: {}", key_path.display());
        eprintln!("  Protect this file with filesystem permissions (0600).");
        signet_core::generate_and_save(&signet_dir, "claude-agent", None, None, None)?;
    }

    let signet_bin = signet_bin()?;

    // Note: ${{...}} is Rust format-string escaping, produces ${...} in output
    let skill_md = format!(
        r#"---
name: signet
version: 0.4.0
description: |
  Cryptographic signing for every tool call. Signs each tool call with Ed25519,
  appends to hash-chained audit log. Use when asked to "enable signet",
  "sign tool calls", "audit mode", or "secure mode".
allowed-tools:
  - Bash
  - Read
hooks:
  PostToolUse:
    - matcher: "*"
      hooks:
        - type: command
          command: "bash ${{CLAUDE_SKILL_DIR}}/bin/sign-tool-call.sh"
          timeout: 5
          statusMessage: "Signing tool call..."
---

# /signet — Cryptographic Tool Call Signing

Signet is active. Every tool call is signed with Ed25519 and logged to a hash-chained audit trail.

Agent identity: `claude-agent`

## Quick Commands

To see recent actions:
```bash
{signet_bin} audit --since 1h
```

To verify chain integrity:
```bash
{signet_bin} audit --verify
```

To export audit report:
```bash
{signet_bin} audit --export report.json --since 24h
```
"#
    );

    fs::write(skills_dir.join("SKILL.md"), skill_md)
        .with_context(|| format!("failed to write {}", skills_dir.join("SKILL.md").display()))?;

    // Hook script uses --tool-from-env / --params-from-env to avoid shell injection.
    // Values are read by the Rust binary directly from env vars, never interpreted by bash.
    let hook_script = format!(
        r#"#!/bin/bash
# Signet PostToolUse hook — signs every tool call
# Uses --tool-from-env/--params-from-env to read env vars safely in Rust,
# avoiding shell interpretation of TOOL_INPUT content.
SIGNET_HOOK_LOG="$HOME/.signet/hook-errors.log"

"{signet_bin}" sign \
  --key claude-agent \
  --tool-from-env TOOL_NAME \
  --params-from-env TOOL_INPUT \
  --target "claude-code://local" \
  > /dev/null 2>&1

exit_code=$?
if [ $exit_code -ne 0 ]; then
  mkdir -p "$HOME/.signet"
  echo "[$(date -u +%FT%TZ)] WARN: signing failed (exit $exit_code) tool=${{TOOL_NAME:-unknown}}" \
    >> "$SIGNET_HOOK_LOG"
fi
"#
    );

    let hook_path = bin_dir.join("sign-tool-call.sh");
    fs::write(&hook_path, hook_script)
        .with_context(|| format!("failed to write {}", hook_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))?;
    }

    eprintln!("Signet installed for Claude Code!");
    eprintln!("  Skill: ~/.claude/skills/signet/");
    eprintln!("  Agent: claude-agent");
    eprintln!();
    eprintln!("Activate with: /signet");
    eprintln!("View audit: signet audit --since 1h");

    Ok(())
}

fn uninstall() -> Result<()> {
    let skills_dir = claude_skills_dir()?;
    if skills_dir.exists() {
        fs::remove_dir_all(&skills_dir)?;
        eprintln!("Signet skill removed from Claude Code.");
    } else {
        eprintln!("Signet skill not found.");
    }
    Ok(())
}

fn audit() -> Result<()> {
    use signet_core::audit::{self, AuditFilter};

    let dir = signet_core::default_signet_dir();
    let filter = AuditFilter {
        since: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        ..Default::default()
    };
    let records = audit::query(&dir, &filter)?;

    if records.is_empty() {
        println!("No signed tool calls in the last hour.");
        return Ok(());
    }

    println!("{:<30} {:<15} {:<30}", "TIME", "TOOL", "TARGET");
    println!("{}", "-".repeat(75));
    for record in &records {
        let r = &record.receipt;
        let ts = r
            .get("ts")
            .or_else(|| r.get("ts_request"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let tool = r
            .get("action")
            .and_then(|a| a.get("tool"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let target = r
            .get("action")
            .and_then(|a| a.get("target"))
            .and_then(|v| v.as_str())
            .unwrap_or("claude-code://local");
        println!("{:<30} {:<15} {}", ts, tool, target);
    }
    println!("\n{} signed tool calls", records.len());

    Ok(())
}
