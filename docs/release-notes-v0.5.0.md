# Signet v0.5.0 Release Notes

Post to: https://github.com/Prismer-AI/signet/releases/new?tag=v0.5.0

---

## Signet v0.5.0 — Dashboard, Python Bilateral, Security Hardening

**Your AI agent just called a tool. Now you can see what happened.**

This release adds a local web dashboard, completes the Python SDK with bilateral signing, closes all tracked security issues, and ships 10 framework integrations.

### Dashboard — `signet dashboard`

New CLI subcommand that starts a local web viewer at `localhost:9191`:

```bash
signet dashboard --open
```

Four views:
- **Timeline** — browse receipts with signer/tool/time filters, click to expand full JSON
- **Chain Integrity** — one-click hash chain verification with break point details
- **Signature Verification** — pass/fail counts with failure reasons
- **Stats** — aggregate breakdowns by tool, signer, and receipt version

Supports v1 (dispatch), v2 (compound), and v3 (bilateral) receipts. Zero dependencies beyond the CLI binary.

### Python SDK — Bilateral Signing

`SigningAgent` now supports bilateral (co-signing) workflows:

```python
from signet_auth import SigningAgent

client = SigningAgent.create("client-agent")
server = SigningAgent.create("server-agent")

receipt = client.sign("web_search", params={"query": "signet"})
bilateral = server.sign_bilateral(receipt, response_content={"results": ["a", "b"]})
assert server.verify_bilateral_receipt(bilateral)
```

### Framework Optional Dependencies

Install with framework extras:

```bash
pip install signet-auth[langchain]      # LangChain / LangGraph
pip install signet-auth[llamaindex]     # LlamaIndex
pip install signet-auth[google-adk]     # Google ADK
pip install signet-auth[pydantic-ai]    # Pydantic AI
pip install signet-auth[semantic-kernel] # Semantic Kernel
pip install signet-auth[all]            # All frameworks
```

### Security Hardening (17 issues fixed)

- **CRITICAL**: `signet_sign` MCP tool no longer accepts `secret_key` as argument — keys are read exclusively from `SIGNET_SECRET_KEY` env var
- **HIGH**: Audit log `append()` now uses `fs2` file locking to prevent concurrent writers from corrupting the hash chain
- **HIGH**: `BilateralVerifyOptions` gains `trusted_agent_pubkey` field to close the self-trust gap
- **HIGH**: Release pipeline no longer silently swallows publish failures (`|| true` → version-already-published check)
- `params_hash` format validation (rejects malformed hashes)
- `load_key_info` validates filename matches content name field
- `NonceCache` maxSize (default 100k) prevents OOM
- `signing-transport` warns when no `trustedServerKeys` configured
- Regex compiled once via `LazyLock`
- CI pins nightly Rust version

### Other Changes

- Pydantic AI integration rewritten from broken `AbstractCapability` to `SignetMiddleware` (wrap/wrap_async decorators)
- Centralized version management via `VERSION` file + `scripts/version-sync.mjs`
- CI now tests all 5 npm packages (was missing mcp-server, mcp-tools, vercel-ai)
- README risk-first narrative rewrite
- End-to-end demo SVG
- Claude Code plugin install updated for official marketplace

### Install / Upgrade

```bash
# CLI
cargo install signet-cli

# Python
pip install signet-auth==0.5.0

# TypeScript
npm install @signet-auth/core@0.5.0
```

### Links

- [Full documentation](https://github.com/Prismer-AI/signet)
- [Dashboard demo (MP4)](https://github.com/Prismer-AI/signet/blob/main/demo-delegation-full.mp4)
- [PyPI](https://pypi.org/project/signet-auth/) · [npm](https://www.npmjs.com/org/signet-auth) · [crates.io](https://crates.io/crates/signet-core)

If Signet is useful to you, [star the repo](https://github.com/Prismer-AI/signet) to help others discover it.
