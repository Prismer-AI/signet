# Signet TODOs

Deferred items from reviews and implementation. Each entry lists What, Why, Effort (S/M/L with human + CC estimates), and Depends on.

Effort scale: S = small (< 1 day human / < 30 min CC), M = medium (1–3 days human / 1–2 hr CC), L = large (1–2 weeks human / 4–8 hr CC).

---

## P1 — Next (post-traction)

### Python Binding (PyO3)

**What:** Rust-to-Python binding exposing `sign`, `verify`, and `identity` via PyO3. Published to PyPI as `signet-auth`.

**Why:** Covers the LangChain, CrewAI, and AutoGen ecosystem. Without a Python binding, Signet is invisible to the majority of agent developers.

**Effort:** M — ~2 days human / ~1 hr CC

**Depends on:** traction signal from v0.1

---

### Homebrew Tap

**What:** `homebrew-signet` tap so macOS developers can `brew install signet`.

**Why:** macOS developers expect Homebrew. Reduces friction for CLI adoption outside the Rust ecosystem.

**Effort:** S — ~2 hr human / ~15 min CC

**Depends on:** release binary workflow (GitHub Releases with prebuilt binaries)

---

## P2 — Medium Term

### Encrypted Parameter Storage

**What:** `signet sign --encrypt-params` encrypts the `params` field in the JSONL audit log using XChaCha20-Poly1305 with the agent's identity key.

**Why:** Audit logs may contain sensitive tool arguments (e.g. file paths, API inputs). Encryption allows auditing without exposing raw params.

**Effort:** M — ~1.5 days human / ~1 hr CC

**Depends on:** M2 audit module (signet-core audit writer)

---

### Delegation Chains

**What:** Agent A can cryptographically authorize Agent B to act on its behalf. Chain verification proves the full authorization path.

**Why:** Multi-agent systems require scoped authority. Without delegation, every sub-agent must hold root keys — a security anti-pattern.

**Effort:** L — ~1.5 weeks human / ~6 hr CC

**Depends on:** identity registry (centralized or embedded key registry)

---

### Server-Side Verification Middleware

**What:** MCP servers can optionally verify incoming Signet signatures before executing tool calls. Ships as a middleware for common MCP server frameworks.

**Why:** Bilateral verification closes the trust loop. Single-sided attestation alone means servers cannot enforce signing policy.

**Effort:** L — ~1 week human / ~5 hr CC

**Depends on:** adoption (at least one real MCP server to integrate against)

---

## P3 — Long Term

### OAGS Conformance

**What:** Align Signet's receipt and identity formats with the Open Agent Governance Specification where the spec has stabilized.

**Why:** Standards alignment reduces integration friction and positions Signet as infrastructure rather than a proprietary SDK.

**Effort:** M — ~2 days human / ~1 hr CC

**Depends on:** OAGS spec stabilization

---

### Off-Host Chain Anchoring

**What:** Periodically anchor audit log chain hashes to an external service (e.g. a transparency log or content-addressed store) for durable tamper evidence independent of local storage.

**Why:** Local-only hash chains can be deleted or replaced. External anchoring provides third-party verifiable tamper evidence.

**Effort:** L — ~1.5 weeks human / ~6 hr CC

**Depends on:** nothing (can be added as an optional sink)

---

### TUI Dashboard

**What:** `signet dashboard` command using ratatui for real-time audit log visualization — scrollable timeline, per-tool stats, hash chain status.

**Why:** Teams auditing agent activity need a faster interface than raw `signet audit` output.

**Effort:** M — ~3 days human / ~2 hr CC

**Depends on:** nothing

---

### Binary Signing

**What:** Sign Signet release binaries with Signet itself. Include receipts in GitHub Releases.

**Why:** Dogfooding the tool on its own release pipeline demonstrates the model and builds trust with security-conscious adopters.

**Effort:** S — ~3 hr human / ~20 min CC

**Depends on:** release binary workflow

---

### Windows Support

**What:** Windows binary in CI (GitHub Actions `windows-latest`), plus correct file permission handling (replacing Unix `0o600` calls).

**Why:** A significant portion of developers run Windows. Missing Windows support creates a perception of poor cross-platform quality.

**Effort:** M — ~2 days human / ~1 hr CC

**Depends on:** nothing (self-contained)

---

### Agent Framework Integrations

**What:** Native integrations for each framework — LangChain callback handler, CrewAI hook, AutoGen middleware — wrapping the Python binding.

**Why:** Developers adopt trust tooling at the framework layer, not the raw SDK layer. Drop-in handlers lower the bar to zero.

**Effort:** M per framework — ~1.5 days human / ~1 hr CC each

**Depends on:** Python binding (PyO3)
