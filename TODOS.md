# Signet TODOs

Deferred items from reviews and implementation.

## P1 — Next (post-traction)

### Python Binding (PyO3)
Rust to Python binding covering sign/verify/identity. Covers LangChain/CrewAI/AutoGen ecosystem.
**Effort:** M | **Depends on:** traction signal from v0.1

### Homebrew Tap
`brew install signet` via homebrew-signet tap. macOS developers expect Homebrew.
**Effort:** S | **Depends on:** release binary workflow

## P2 — Medium Term

### Encrypted Parameter Storage
`signet sign --encrypt-params` encrypts params in audit log with XChaCha20-Poly1305.
**Effort:** M | **Depends on:** M2 audit module

### Delegation Chains
Agent A authorizes Agent B with cryptographic proof. Multi-party authorization.
**Effort:** L | **Depends on:** identity registry

### Server-Side Verification
MCP servers optionally verify signatures before executing tool calls.
**Effort:** L | **Depends on:** adoption

## P3 — Long Term

### OAGS Conformance
Align with Open Agent Governance Specification.
**Effort:** M | **Depends on:** OAGS spec stabilization

### Off-Host Chain Anchoring
Anchor audit chain hashes to external service for durable tamper-evidence.
**Effort:** L

### TUI Dashboard
`signet dashboard` with ratatui for real-time audit log visualization.
**Effort:** M

### Binary Signing
Sign Signet release binaries with Signet itself.
**Effort:** S | **Depends on:** release workflow

### Windows Support
Windows binary in CI + file permission handling.
**Effort:** M

### Agent Framework Integrations
LangChain callback handler, CrewAI hook, Claude Code plugin.
**Effort:** M per framework | **Depends on:** Python binding
