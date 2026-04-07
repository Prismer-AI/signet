# signet-core

Cryptographic action receipts for AI agents. Ed25519 signing and verification for tool calls — offline-verifiable, tamper-evident, portable.

[![crates.io](https://img.shields.io/crates/v/signet-core?style=flat-square)](https://crates.io/crates/signet-core)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

## Install

```toml
[dependencies]
signet-core = "0.4"
```

## Usage

```rust
use signet_core::{Identity, sign_action, verify_receipt, SignetAction};

let identity = Identity::generate("my-agent");

let action = SignetAction {
    tool: "web_search".to_string(),
    params: serde_json::json!({ "query": "signet" }),
    params_hash: "".to_string(),
    target: "mcp://local".to_string(),
    transport: "stdio".to_string(),
};

let receipt = sign_action(&identity, action)?;
assert!(verify_receipt(&receipt, &identity.public_key()));
```

## CLI

```bash
cargo install signet-cli
signet identity generate --name my-agent
signet sign --key my-agent --tool web_search --params '{"query":"signet"}' --target mcp://local
```

## Links

- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)
- [Python (signet-auth)](https://pypi.org/project/signet-auth/)
- [npm (@signet-auth/core)](https://www.npmjs.com/package/@signet-auth/core)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
