# Distribution + Launch Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Signet installable via npm/cargo/GitHub Releases with CI quality gates, and add standard open-source docs.

**Architecture:** GitHub Actions for CI + release. npm workspace publish for TS packages. crates.io for Rust. Cross-compile release binaries via `cross` or native runners.

**Tech Stack:** GitHub Actions, wasm-pack, npm, cargo, cross-rs

**Existing:** v0.1.0 tagged + released (no binaries). 83 tests. Packages have valid package.json/Cargo.toml.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `.github/workflows/ci.yml` | Create | Test on push/PR: cargo test + wasm + npm test + clippy |
| `.github/workflows/release.yml` | Create | On tag push: build binaries + attach to GH release |
| `.github/ISSUE_TEMPLATE/bug_report.md` | Create | Bug report template |
| `.github/ISSUE_TEMPLATE/feature_request.md` | Create | Feature request template |
| `CHANGELOG.md` | Create | v0.1.0 changelog |
| `CONTRIBUTING.md` | Create | Build guide + contribution workflow |
| `TODOS.md` | Create | Consolidated deferred items |
| `README.md` | Modify | Add badges |

---

### Task 1: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create CI workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always

jobs:
  rust:
    name: Rust Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - uses: Swatinem/rust-cache@v2
      - name: Clippy
        run: cargo clippy --workspace -- -D warnings
      - name: Test
        run: cargo test --workspace
      - name: Check no unsafe
        run: |
          if grep -r "unsafe" crates/signet-core/src/ signet-cli/src/; then
            echo "Found unsafe code!"
            exit 1
          fi

  wasm:
    name: WASM Build + Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          targets: wasm32-unknown-unknown
      - uses: Swatinem/rust-cache@v2
      - name: Install wasm-pack
        run: cargo install wasm-pack
      - name: Build WASM
        run: wasm-pack build bindings/signet-ts --target nodejs --out-dir pkg
      - name: Run WASM tests
        run: node examples/wasm-roundtrip/test.mjs

  typescript:
    name: TypeScript Tests
    runs-on: ubuntu-latest
    needs: wasm
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          targets: wasm32-unknown-unknown
      - uses: Swatinem/rust-cache@v2
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - name: Install wasm-pack
        run: cargo install wasm-pack
      - name: Build WASM into packages
        run: wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm
      - name: Install npm deps
        run: npm install
        working-directory: packages/signet-mcp
      - name: Test @signet/core
        run: npx tsc && cp -r wasm dist/wasm && node --test dist/tests/core.test.js
        working-directory: packages/signet-core
      - name: Test @signet/mcp
        run: npx tsc && node --test dist/tests/mcp.test.js
        working-directory: packages/signet-mcp
```

- [ ] **Step 2: Verify locally (dry run)**

```bash
# Simulate what CI does
~/.cargo/bin/cargo clippy --workspace -- -D warnings
~/.cargo/bin/cargo test --workspace
~/.cargo/bin/wasm-pack build bindings/signet-ts --target nodejs --out-dir pkg
node examples/wasm-roundtrip/test.mjs
```
Expected: all pass

- [ ] **Step 3: Commit**

```bash
mkdir -p .github/workflows
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow for Rust + WASM + TypeScript tests"
```

---

### Task 2: Release Workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create release workflow**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  build:
    name: Build ${{ matrix.target }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
            artifact: signet-linux-amd64
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
            artifact: signet-linux-arm64
          - target: x86_64-apple-darwin
            os: macos-latest
            artifact: signet-darwin-amd64
          - target: aarch64-apple-darwin
            os: macos-latest
            artifact: signet-darwin-arm64
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          targets: ${{ matrix.target }}
      - name: Install cross-compilation tools
        if: matrix.target == 'aarch64-unknown-linux-gnu'
        run: |
          sudo apt-get update
          sudo apt-get install -y gcc-aarch64-linux-gnu
          echo '[target.aarch64-unknown-linux-gnu]' >> ~/.cargo/config.toml
          echo 'linker = "aarch64-linux-gnu-gcc"' >> ~/.cargo/config.toml
      - name: Build release binary
        run: cargo build --release --target ${{ matrix.target }} -p signet-cli
      - name: Package
        run: |
          mkdir -p dist
          cp target/${{ matrix.target }}/release/signet dist/${{ matrix.artifact }}
          chmod +x dist/${{ matrix.artifact }}
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.artifact }}
          path: dist/${{ matrix.artifact }}

  release:
    name: Attach binaries to release
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: artifacts
      - name: Attach to release
        uses: softprops/action-gh-release@v2
        with:
          files: artifacts/**/*
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add release workflow for cross-platform binaries"
```

---

### Task 3: CHANGELOG.md

**Files:**
- Create: `CHANGELOG.md`

- [ ] **Step 1: Create CHANGELOG**

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-29

### Added
- **signet-core**: Ed25519 identity generation with Argon2id + XChaCha20-Poly1305 encrypted storage
- **signet-core**: Action signing with RFC 8785 (JCS) canonical JSON
- **signet-core**: Offline signature verification
- **signet-core**: Append-only JSONL audit log with SHA-256 hash chain
- **signet-cli**: `signet identity generate/list/export` commands
- **signet-cli**: `signet sign` with `--hash-only`, `--output`, `@file` params, `--no-log`
- **signet-cli**: `signet verify` for receipt verification + `--chain` for hash chain integrity
- **signet-cli**: `signet audit` with `--since`, `--tool`, `--signer`, `--verify`, `--export`
- **@signet/core**: TypeScript wrapper for WASM crypto functions
- **@signet/mcp**: SigningTransport middleware for MCP tool call signing
- WASM binding (wasm-bindgen) for Node.js
- End-to-end MCP agent example (agent + echo server)

[0.1.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.1.0
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add CHANGELOG.md for v0.1.0"
```

---

### Task 4: CONTRIBUTING.md

**Files:**
- Create: `CONTRIBUTING.md`

- [ ] **Step 1: Create CONTRIBUTING.md**

```markdown
# Contributing to Signet

Thanks for your interest in contributing! Signet is an open-source project
and we welcome contributions of all kinds.

## Getting Started

### Prerequisites

- Rust (1.70+ nightly)
- wasm-pack (`cargo install wasm-pack`)
- Node.js (18+)

### Build

```bash
# Clone
git clone https://github.com/Prismer-AI/signet.git
cd signet

# Rust core + CLI
cargo build -p signet-cli

# WASM binding
wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm

# TypeScript packages
cd packages/signet-core && npx tsc && cp -r wasm dist/wasm
cd ../signet-mcp && npm install && npx tsc
```

### Test

```bash
# Rust (64 tests)
cargo test --workspace

# WASM roundtrip (8 tests)
wasm-pack build bindings/signet-ts --target nodejs --out-dir pkg
node examples/wasm-roundtrip/test.mjs

# TypeScript (11 tests)
cd packages/signet-core && npm test
cd packages/signet-mcp && npm test
```

### Lint

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

## Development Workflow

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes with tests
4. Run the full test suite
5. Commit with conventional commits (`feat:`, `fix:`, `test:`, `docs:`)
6. Open a PR against `main`

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(core):` — new feature in signet-core
- `feat(cli):` — new feature in signet-cli
- `feat(wasm):` — WASM binding changes
- `feat(mcp):` — @signet/mcp changes
- `fix:` — bug fix
- `test:` — test changes
- `docs:` — documentation
- `ci:` — CI/CD changes
- `refactor:` — code refactoring

## Project Structure

```
crates/signet-core/       Rust core library
signet-cli/               CLI binary
bindings/signet-ts/       WASM binding (Rust → wasm-bindgen)
packages/signet-core/     @signet/core (TypeScript wrapper)
packages/signet-mcp/      @signet/mcp (MCP middleware)
examples/                 Usage examples
docs/                     Design docs and specs
```

## Architecture Notes

- `signet-core` is the source of truth for all crypto logic
- TypeScript packages wrap WASM, they don't re-implement crypto
- Filesystem-dependent code is gated with `#[cfg(not(target_arch = "wasm32"))]`
- All public functions must have tests
- No `unsafe` code in signet-core or signet-cli

## License

By contributing, you agree that your contributions will be licensed under
the Apache-2.0 OR MIT dual license.
```

- [ ] **Step 2: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs: add CONTRIBUTING.md with build guide and workflow"
```

---

### Task 5: Issue Templates

**Files:**
- Create: `.github/ISSUE_TEMPLATE/bug_report.md`
- Create: `.github/ISSUE_TEMPLATE/feature_request.md`

- [ ] **Step 1: Create bug report template**

```markdown
---
name: Bug Report
about: Report a bug in Signet
labels: bug
---

## Description

A clear description of the bug.

## Steps to Reproduce

1. ...
2. ...
3. ...

## Expected Behavior

What should happen.

## Actual Behavior

What actually happens.

## Environment

- OS: [e.g. macOS 14, Ubuntu 22.04]
- Rust version: [e.g. 1.78-nightly]
- Signet version: [e.g. 0.1.0]
- Node.js version (if TS): [e.g. 22.0.0]

## Additional Context

Logs, screenshots, or other relevant information.
```

- [ ] **Step 2: Create feature request template**

```markdown
---
name: Feature Request
about: Suggest an improvement to Signet
labels: enhancement
---

## Problem

What problem does this solve? What's the use case?

## Proposed Solution

How should it work?

## Alternatives Considered

What other approaches did you think about?

## Additional Context

Any relevant links, examples, or prior art.
```

- [ ] **Step 3: Commit**

```bash
mkdir -p .github/ISSUE_TEMPLATE
git add .github/ISSUE_TEMPLATE/
git commit -m "docs: add issue templates for bug reports and feature requests"
```

---

### Task 6: TODOS.md

**Files:**
- Create: `TODOS.md`

- [ ] **Step 1: Create TODOS.md consolidating all deferred items**

```markdown
# Signet TODOs

Deferred items from CEO review, eng review, and implementation.

## P1 — Next (post-traction signal)

### Python Binding (PyO3)
**What:** Rust → Python binding via PyO3, covering sign/verify/identity.
**Why:** LangChain, CrewAI, AutoGen are all Python. TS-only limits addressable market to ~50%.
**Effort:** M (human: 1 week / CC: ~1 hour)
**Depends on:** Traction signal from v0.1 (50+ npm downloads/week)

### Homebrew Tap
**What:** `brew install signet` via homebrew-signet tap repo.
**Why:** macOS developers expect Homebrew. cargo install requires Rust toolchain.
**Effort:** S (human: 2 hours / CC: ~15 min)
**Depends on:** Release binary workflow (done)

## P2 — Medium Term

### Encrypted Parameter Storage
**What:** `signet sign --encrypt-params` encrypts params in audit log with XChaCha20-Poly1305.
**Why:** Audit logs may contain sensitive data (API keys, PII in tool params).
**Effort:** M (human: 3 days / CC: ~30 min)
**Depends on:** M2 audit module (done). Key management for param encryption TBD.

### Delegation Chains
**What:** Agent A authorizes Agent B to act on its behalf, with cryptographic proof.
**Why:** This is the "DocuSign moment" — multi-party authorization.
**Effort:** L (human: 2 weeks / CC: ~3 hours)
**Depends on:** Identity registry (not started)

### Server-Side Verification Middleware
**What:** MCP servers can optionally verify signatures before executing tool calls.
**Why:** Turns Signet from single-sided attestation to bilateral protocol.
**Effort:** L (human: 2 weeks / CC: ~2 hours)
**Depends on:** Adoption. Chicken-and-egg: servers won't verify until clients sign.

## P3 — Long Term

### OAGS Conformance
**What:** Align with Open Agent Governance Specification.
**Why:** Standards compatibility, ecosystem legitimacy.
**Effort:** M
**Depends on:** OAGS spec stabilization (currently draft v0.1)

### Off-Host Chain Anchoring
**What:** Anchor audit chain hashes to an external service (e.g., transparency log).
**Why:** Local hash chain can be rewritten if machine is compromised. Off-host anchoring provides durable tamper-evidence.
**Effort:** L
**Depends on:** Choosing an anchoring backend

### TUI Dashboard
**What:** `signet dashboard` with ratatui for real-time audit log visualization.
**Why:** Visual appeal, developer experience.
**Effort:** M

### Binary Signing
**What:** Sign Signet release binaries with Signet itself (eat our own dogfood).
**Why:** Trust chain from source to binary. Great marketing too.
**Effort:** S
**Depends on:** Release binary workflow (done)

### Windows Support
**What:** Windows binary in CI + file permission handling for Windows.
**Why:** Not all developers are on Unix.
**Effort:** M

### Agent Framework Integrations
**What:** LangChain callback handler, CrewAI hook, Claude Code plugin.
**Why:** Meet developers where they are.
**Effort:** M per framework
**Depends on:** Python binding (for LangChain/CrewAI)
```

- [ ] **Step 2: Commit**

```bash
git add TODOS.md
git commit -m "docs: add TODOS.md with consolidated deferred items from all reviews"
```

---

### Task 7: README Badges

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add badges after the title**

Add after `# Signet` on line 1:

```markdown
# Signet

[![CI](https://github.com/Prismer-AI/signet/actions/workflows/ci.yml/badge.svg)](https://github.com/Prismer-AI/signet/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/signet-core.svg)](https://crates.io/crates/signet-core)
[![npm](https://img.shields.io/npm/v/@signet/mcp.svg)](https://www.npmjs.com/package/@signet/mcp)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-blue.svg)](LICENSE-APACHE)
```

Note: crates.io and npm badges will show "not found" until packages are actually published. They'll auto-update once published.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add CI, crates.io, npm, and license badges to README"
```

---

### Task 8: Push + Verify CI

- [ ] **Step 1: Push all changes**

```bash
git push origin main
```

- [ ] **Step 2: Verify CI runs**

```bash
gh run list --limit 1
```
Expected: CI workflow triggered on push, running or completed

- [ ] **Step 3: Watch CI result**

```bash
gh run watch
```
Expected: all 3 jobs pass (rust, wasm, typescript)

- [ ] **Step 4: If CI fails, fix and re-push**

Read the failure output:
```bash
gh run view --log-failed
```
Fix the issue, commit, push again.

---

### Task 9: npm + crates.io Publish (manual)

This task requires manual authentication. Do NOT automate token handling.

- [ ] **Step 1: Publish signet-core to crates.io**

```bash
cd /home/willamhou/codes/signet
~/.cargo/bin/cargo publish -p signet-core
```

Note: may need `cargo login` first with a crates.io API token.

- [ ] **Step 2: Build WASM for publish**

```bash
~/.cargo/bin/wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm
```

- [ ] **Step 3: Publish @signet/core to npm**

```bash
cd packages/signet-core
npx tsc && cp -r wasm dist/wasm
npm publish --access public
```

Note: may need `npm login` first. Scope `@signet` must be created on npm first.

- [ ] **Step 4: Publish @signet/mcp to npm**

```bash
cd packages/signet-mcp
npx tsc
npm publish --access public
```

- [ ] **Step 5: Verify**

```bash
npm info @signet/core version
npm info @signet/mcp version
cargo search signet-core
```
Expected: all show 0.1.0

---

## Checklist

| # | Item | Verified by |
|---|------|-------------|
| 1 | CI passes on push | Task 8 |
| 2 | Release workflow builds binaries on tag | Manual: push a test tag |
| 3 | CHANGELOG.md exists | Task 3 |
| 4 | CONTRIBUTING.md exists | Task 4 |
| 5 | Issue templates exist | Task 5 |
| 6 | TODOS.md consolidates all deferred items | Task 6 |
| 7 | README has badges | Task 7 |
| 8 | npm packages published | Task 9 |
| 9 | crates.io package published | Task 9 |
