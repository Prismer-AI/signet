# Signet Release Notes — All Versions

Copy each section to the corresponding GitHub Release page.

---

## v0.2.0 — Compound Receipts + TypeScript MCP Middleware (2026-04-02)

First multi-language release with compound receipts that bind request and response.

### Highlights
- **Compound receipts (v2)** — sign both request and response in a single receipt with `sign_compound()`
- **TypeScript MCP middleware** — `@signet-auth/mcp` wraps any MCP transport with `SigningTransport`
- **Cross-language key format** — unified 64-byte keypair format across Rust, TypeScript (WASM), and Python
- **`@signet-auth/core`** — WASM-backed TypeScript package for signing and verification

### Breaking Changes
- Key format changed from raw 32-byte seed to 64-byte keypair (ed25519-dalek compatible)
- `sign()` and `verify()` signatures updated across all languages

---

## v0.3.0 — Server-Side Verification (2026-04-03)

Verification moves to the execution boundary. Servers can now reject unsigned, tampered, or stale requests before running them.

### Highlights
- **`@signet-auth/mcp-server`** — `verifyRequest()` checks signature validity, freshness, target binding, and tool/params matching at the server boundary
- **`NonceCache`** — replay protection for MCP servers
- **CLI demo recordings** — `demo-cli.svg` and `demo-mcp.svg` added to README
- **Server verification guide** — docs/guides/mcp-integration.md

---

## v0.4.0 — Bilateral Co-Signing (2026-04-06)

Both sides walk away with proof. The server co-signs the agent's receipt after verification.

### Highlights
- **Bilateral receipts (v3)** — `signBilateral()` / `signResponse()` let the server co-sign the agent's receipt
- **`verifyBilateral()`** — verify both signatures in one call, with timestamp ordering and time window checks
- **`@signet-auth/mcp-tools`** — standalone MCP server exposing `signet_sign`, `signet_verify`, `signet_generate_keypair`, `signet_content_hash`
- **AutoGen integration** — `SignetAutogenHook` for AutoGen 0.4
- **Claude Code plugin** — PostToolUse hook, WASM signing, hash-chained audit
- **`signet claude install/uninstall`** CLI commands
- **Richer audit trail** — `session`, `call_id`, `response_hash` fields in Action

---

## v0.4.1–v0.4.4 — Stabilization (2026-04-06 – 2026-04-07)

Bug fixes, key format unification, and Codex review fixes.

- Unified key format to 32-byte seed across all packages
- Fixed 8 issues from Codex cross-model review
- `wasm_pubkey_from_seed` for WASM key derivation
- `params_hash` auto-computation in signing functions

---

## v0.4.5 — README Rewrite + Execution Boundary Demo (2026-04-08)

Growth-focused release: README risk-first narrative, execution boundary demo, package badges.

### Highlights
- **README rewrite** — "Your AI agent just called a tool. Can you prove what it did?"
- **Execution boundary demo** — SVG/MP4/GIF showing server rejecting unsigned, tampered, stale, and mis-targeted requests
- **Choose Your Path** — four onboarding paths: Claude Code, Codex, MCP client, MCP server
- **Package READMEs** — all 5 npm packages + PyPI + crates.io have independent READMEs with Star CTA
- **`@signet-auth/vercel-ai`** — Vercel AI SDK callbacks for signing tool calls

---

## v0.4.6 — Security Hardening + Python Bilateral (2026-04-08)

17 security issues fixed, Python SDK completed with bilateral signing.

### Highlights
- **17 bug fixes** from cross-model review (Claude + Codex)
- **`SigningAgent.sign_bilateral()`** — Python bilateral signing
- **`pip install signet-auth[langchain]`** — optional deps for 10 frameworks
- **Pydantic AI rewrite** — `SignetMiddleware` with `wrap()`/`wrap_async()` decorators
- **Centralized versioning** — `VERSION` file + `version-sync.mjs` + CI enforcement
- **CI**: all 5 npm packages tested, nightly Rust pinned, publish errors surfaced

### Security Fixes
- CRITICAL: `signet_sign` MCP tool — secret key moved to env var only
- HIGH: Audit log file locking (fs2)
- HIGH: `trusted_agent_pubkey` in bilateral verification
- HIGH: Release pipeline error handling
- 13 additional MEDIUM/LOW fixes

---

## v0.5.0 — Dashboard + Full Release (2026-04-08)

See [v0.5.0 Release Notes](release-notes-v0.5.0.md) for full details.
