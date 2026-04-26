use anyhow::Result;

/// One-command setup: generate identity, sign a test action, show audit.
pub fn quickstart() -> Result<()> {
    let dir = signet_core::default_signet_dir();

    eprintln!("=== Signet Quickstart ===\n");

    // 1. Generate identity (skip if exists)
    let key_name = "signet-agent";
    let key_exists = signet_core::load_key_info(&dir, key_name).is_ok();

    if key_exists {
        let info = signet_core::load_key_info(&dir, key_name)?;
        eprintln!(
            "1. Identity '{}' already exists ({})",
            key_name, info.pubkey
        );
    } else {
        signet_core::generate_and_save(&dir, key_name, Some("quickstart"), None, None)?;
        let info = signet_core::load_key_info(&dir, key_name)?;
        eprintln!("1. Created identity '{}' ({})", key_name, info.pubkey);
    }

    // 2. Sign a test action
    let sk = signet_core::load_signing_key(&dir, key_name, None)?;
    let action = signet_core::Action {
        tool: "quickstart_test".to_string(),
        params: serde_json::json!({"message": "Hello from Signet!"}),
        params_hash: String::new(),
        target: "mcp://quickstart".to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };

    let receipt = signet_core::sign(&sk, &action, key_name, "quickstart")?;
    let receipt_json = serde_json::to_value(&receipt)?;
    signet_core::audit::append(&dir, &receipt_json)?;
    eprintln!("2. Signed test action ({})", receipt.id);

    // 3. Verify
    let info = signet_core::load_key_info(&dir, key_name)?;
    let vk = signet_core::load_verifying_key(&dir, key_name)?;
    let valid = signet_core::verify(&receipt, &vk).is_ok();
    eprintln!(
        "3. Verified: {}",
        if valid { "✓ valid" } else { "✗ invalid" }
    );

    // 4. Show summary
    eprintln!("\n=== Ready! ===\n");
    eprintln!("Identity:  {} ({})", key_name, info.pubkey);
    eprintln!("Keys:      {}/keys/", dir.display());
    eprintln!("Audit log: {}/audit/", dir.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!(
        "  signet sign --key {} --tool <name> --params '{{}}' --target mcp://server",
        key_name
    );
    eprintln!("  signet audit --since 1h");
    eprintln!("  signet verify --chain");
    eprintln!("  signet dashboard");
    eprintln!();
    eprintln!("Python:");
    eprintln!("  from signet_auth import SigningAgent");
    eprintln!("  agent = SigningAgent(\"{key_name}\")");
    eprintln!("  receipt = agent.sign(\"my_tool\", params={{\"key\": \"value\"}})");

    Ok(())
}
