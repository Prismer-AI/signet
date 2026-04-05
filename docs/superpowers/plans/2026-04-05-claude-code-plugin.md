# Claude Code Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Claude Code plugin that signs every tool call with Ed25519 via WASM, with zero npm dependencies.

**Architecture:** PostToolUse hook reads stdin JSON, signs with embedded WASM binary, appends to hash-chained JSONL audit log at `~/.signet/`. All CommonJS (matching wasm-pack output). Plugin distributed as monorepo subdirectory via Git.

**Tech Stack:** Node.js CommonJS, wasm-pack WASM (Ed25519 + SHA-256 + JCS), Claude Code plugin system.

---

## File Structure

```
plugins/claude-code/
├── .claude-plugin/plugin.json       # Plugin manifest
├── .gitattributes                   # Mark .wasm as binary
├── package.json                     # type: commonjs, zero deps
├── skills/signet/SKILL.md           # /signet skill definition
├── hooks/hooks.json                 # PostToolUse config
├── bin/sign.cjs                     # Hook entry point
├── lib/signet.cjs                   # WASM wrapper
├── lib/audit.cjs                    # JSONL append + hash chain
├── wasm/signet_wasm_bg.wasm         # Pre-built WASM (~475KB)
├── wasm/signet_wasm.js              # wasm-pack CJS glue (copied, unmodified)
├── scripts/build-plugin.sh          # Copy WASM + verify
├── tests/signet.test.cjs            # Tests for lib/signet.cjs
├── tests/audit.test.cjs             # Tests for lib/audit.cjs
├── tests/sign-hook.test.cjs         # Tests for bin/sign.cjs
└── README.md
```

---

### Task 1: Scaffold Plugin Directory + Manifests

**Files:**
- Create: `plugins/claude-code/.claude-plugin/plugin.json`
- Create: `plugins/claude-code/package.json`
- Create: `plugins/claude-code/.gitattributes`
- Create: `plugins/claude-code/hooks/hooks.json`
- Create: `plugins/claude-code/skills/signet/SKILL.md`

- [ ] **Step 1: Create plugin.json**

```bash
mkdir -p plugins/claude-code/.claude-plugin
```

Write `plugins/claude-code/.claude-plugin/plugin.json`:
```json
{
  "name": "signet",
  "description": "Cryptographic signing for every AI agent tool call — Ed25519 receipts + hash-chained audit log",
  "version": "0.4.0",
  "author": { "name": "Prismer AI" },
  "homepage": "https://github.com/Prismer-AI/signet",
  "repository": "https://github.com/Prismer-AI/signet",
  "license": "Apache-2.0 OR MIT",
  "keywords": ["security", "signing", "audit", "ed25519", "mcp"]
}
```

- [ ] **Step 2: Create package.json**

Write `plugins/claude-code/package.json`:
```json
{
  "name": "signet-claude-plugin",
  "version": "0.4.0",
  "type": "commonjs",
  "private": true,
  "scripts": {
    "test": "node --test tests/",
    "build": "bash scripts/build-plugin.sh"
  }
}
```

- [ ] **Step 3: Create .gitattributes**

Write `plugins/claude-code/.gitattributes`:
```
wasm/signet_wasm_bg.wasm binary
```

- [ ] **Step 4: Create hooks.json**

```bash
mkdir -p plugins/claude-code/hooks
```

Write `plugins/claude-code/hooks/hooks.json`:
```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [{
          "type": "command",
          "command": "node \"${CLAUDE_PLUGIN_ROOT}/bin/sign.cjs\"",
          "timeout": 5
        }]
      }
    ]
  }
}
```

- [ ] **Step 5: Create SKILL.md**

```bash
mkdir -p plugins/claude-code/skills/signet
```

Write `plugins/claude-code/skills/signet/SKILL.md`:
```markdown
---
name: signet
description: Cryptographic signing for every tool call with Ed25519 audit trail
---

# /signet — Cryptographic Tool Call Signing

Signet is active. Every tool call is signed with Ed25519 and logged
to a hash-chained audit trail at ~/.signet/audit/.

Agent identity: `claude-agent` (auto-generated on first use)

## Audit Commands

View recent signed tool calls (requires signet CLI):

    signet audit --since 1h

Verify hash chain integrity:

    signet audit --verify

View raw audit log without CLI:

    cat ~/.signet/audit/$(date +%Y-%m-%d).jsonl | jq '.receipt.action.tool'

Export audit report:

    signet audit --export report.json --since 24h
```

- [ ] **Step 6: Commit scaffold**

```bash
git add plugins/claude-code/
git commit -m "feat(plugin): scaffold Claude Code plugin directory structure"
```

---

### Task 2: Copy WASM Artifacts + Build Script

**Files:**
- Create: `plugins/claude-code/wasm/signet_wasm_bg.wasm` (copy)
- Create: `plugins/claude-code/wasm/signet_wasm.js` (copy)
- Create: `plugins/claude-code/scripts/build-plugin.sh`

- [ ] **Step 1: Create build script**

```bash
mkdir -p plugins/claude-code/scripts plugins/claude-code/wasm
```

Write `plugins/claude-code/scripts/build-plugin.sh`:
```bash
#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PLUGIN_DIR/../.." && pwd)"
WASM_SRC="$REPO_ROOT/packages/signet-core/wasm"

if [ ! -f "$WASM_SRC/signet_wasm_bg.wasm" ]; then
  echo "Error: WASM not built. Run first:"
  echo "  wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm"
  exit 1
fi

cp "$WASM_SRC/signet_wasm_bg.wasm" "$PLUGIN_DIR/wasm/"
cp "$WASM_SRC/signet_wasm.js" "$PLUGIN_DIR/wasm/"

echo "WASM copied. Verifying..."
node -e "
  const w = require('$PLUGIN_DIR/wasm/signet_wasm.js');
  const kp = JSON.parse(w.wasm_generate_keypair());
  if (!kp.public_key) throw new Error('WASM verification failed');
  console.log('WASM OK — pubkey:', kp.public_key.slice(0, 20) + '...');
"

echo "Plugin build complete."
```

- [ ] **Step 2: Make build script executable and run it**

```bash
chmod +x plugins/claude-code/scripts/build-plugin.sh
bash plugins/claude-code/scripts/build-plugin.sh
```

Expected: "WASM OK — pubkey: ..." and "Plugin build complete."

- [ ] **Step 3: Commit WASM artifacts + build script**

```bash
git add plugins/claude-code/wasm/ plugins/claude-code/scripts/
git commit -m "feat(plugin): add WASM artifacts and build script"
```

---

### Task 3: Implement lib/signet.cjs (WASM Wrapper)

**Files:**
- Create: `plugins/claude-code/lib/signet.cjs`
- Create: `plugins/claude-code/tests/signet.test.cjs`

- [ ] **Step 1: Write failing tests**

Write `plugins/claude-code/tests/signet.test.cjs`:
```js
'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const signet = require('../lib/signet.cjs');

describe('signet.cjs', () => {
  it('generateKeypair returns publicKey and secretKey', () => {
    const kp = signet.generateKeypair();
    assert.ok(kp.publicKey, 'missing publicKey');
    assert.ok(kp.secretKey, 'missing secretKey');
    assert.ok(kp.publicKey.length > 10, 'publicKey too short');
    assert.ok(kp.secretKey.length > 10, 'secretKey too short');
  });

  it('sign produces a valid receipt', () => {
    const kp = signet.generateKeypair();
    const receipt = signet.sign(kp.secretKey, {
      tool: 'Bash',
      params: { command: 'ls' },
      params_hash: '',
      target: 'claude-code://local',
      transport: 'stdio',
    }, 'test-agent');
    assert.equal(receipt.v, 1);
    assert.equal(receipt.action.tool, 'Bash');
    assert.equal(receipt.signer.name, 'test-agent');
    assert.ok(receipt.sig.startsWith('ed25519:'));
  });

  it('contentHash returns sha256 string', () => {
    const hash = signet.contentHash({ hello: 'world' });
    assert.ok(hash.startsWith('sha256:'));
    // Same input should produce same hash (deterministic)
    assert.equal(hash, signet.contentHash({ hello: 'world' }));
  });

  it('loadOrCreateKey creates key file when missing', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-test-'));
    const keyPath = path.join(tmpDir, 'keys', 'claude-agent.key');
    const result = signet.loadOrCreateKey(keyPath);
    assert.ok(result.publicKey);
    assert.ok(result.secretKey);
    assert.ok(fs.existsSync(keyPath), 'key file should exist');
    // File should have the right structure
    const data = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
    assert.equal(data.v, 1);
    assert.equal(data.algorithm, 'ed25519');
    assert.equal(data.name, 'claude-agent');
    assert.ok(data.seed, 'seed (secret key) should be present');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('loadOrCreateKey reads existing key file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-test-'));
    const keyPath = path.join(tmpDir, 'keys', 'claude-agent.key');
    // Create first
    const kp1 = signet.loadOrCreateKey(keyPath);
    // Load again
    const kp2 = signet.loadOrCreateKey(keyPath);
    assert.equal(kp1.publicKey, kp2.publicKey);
    assert.equal(kp1.secretKey, kp2.secretKey);
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('loadOrCreateKey detects encrypted key file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-test-'));
    const keysDir = path.join(tmpDir, 'keys');
    fs.mkdirSync(keysDir, { recursive: true });
    const keyPath = path.join(keysDir, 'claude-agent.key');
    // Write a fake encrypted key file
    fs.writeFileSync(keyPath, JSON.stringify({
      v: 1, algorithm: 'ed25519', name: 'claude-agent',
      kdf: 'argon2id', ciphertext: 'fake'
    }));
    assert.throws(() => signet.loadOrCreateKey(keyPath), /encrypted/i);
    fs.rmSync(tmpDir, { recursive: true });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd plugins/claude-code && node --test tests/signet.test.cjs
```

Expected: FAIL — `Cannot find module '../lib/signet.cjs'`

- [ ] **Step 3: Implement lib/signet.cjs**

Write `plugins/claude-code/lib/signet.cjs`:
```js
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const wasm = require('../wasm/signet_wasm.js');

/**
 * Generate a new Ed25519 keypair.
 * @returns {{ publicKey: string, secretKey: string }}
 */
function generateKeypair() {
  const result = JSON.parse(wasm.wasm_generate_keypair());
  return { publicKey: result.public_key, secretKey: result.secret_key };
}

/**
 * Sign an action, producing a v1 receipt.
 * @param {string} secretKey - base64 secret key
 * @param {{ tool: string, params: unknown, params_hash: string, target: string, transport: string }} action
 * @param {string} signerName
 * @returns {object} receipt
 */
function sign(secretKey, action, signerName) {
  const json = wasm.wasm_sign(secretKey, JSON.stringify(action), signerName, '');
  return JSON.parse(json);
}

/**
 * Compute SHA-256 hash of canonical JSON (RFC 8785 JCS).
 * @param {unknown} value
 * @returns {string} sha256:hex
 */
function contentHash(value) {
  return wasm.wasm_content_hash(JSON.stringify(value));
}

/**
 * Load or create an unencrypted key file compatible with signet CLI.
 * @param {string} keyPath - full path to .key file
 * @returns {{ publicKey: string, secretKey: string }}
 */
function loadOrCreateKey(keyPath) {
  if (fs.existsSync(keyPath)) {
    const data = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
    if (data.kdf || data.ciphertext) {
      throw new Error(
        'Encrypted key detected at ' + keyPath + '. ' +
        'Run: signet identity generate --name claude-agent --unencrypted'
      );
    }
    // Unencrypted format: { v, algorithm, name, seed }
    // seed is the base64 secret key (32-byte Ed25519 seed)
    const kp = regenerateFromSeed(data.seed);
    return kp;
  }

  // Generate new key and save
  const kp = generateKeypair();
  const keyDir = path.dirname(keyPath);
  fs.mkdirSync(keyDir, { recursive: true });

  const keyFile = {
    v: 1,
    algorithm: 'ed25519',
    name: path.basename(keyPath, '.key'),
    seed: kp.secretKey,
  };
  fs.writeFileSync(keyPath, JSON.stringify(keyFile, null, 2) + '\n', { mode: 0o600 });

  // Also write .pub file for convenience
  const pubPath = keyPath.replace(/\.key$/, '.pub');
  const pubFile = {
    v: 1,
    algorithm: 'ed25519',
    name: keyFile.name,
    pubkey: 'ed25519:' + kp.publicKey,
  };
  fs.writeFileSync(pubPath, JSON.stringify(pubFile, null, 2) + '\n', { mode: 0o644 });

  return kp;
}

/**
 * Re-derive public key from seed by signing and extracting signer.pubkey.
 * The WASM sign function includes the public key in the receipt.
 */
function regenerateFromSeed(seed) {
  const dummyAction = JSON.stringify({
    tool: '_keygen', params: {}, params_hash: '', target: '', transport: '',
  });
  const receipt = JSON.parse(wasm.wasm_sign(seed, dummyAction, '_', ''));
  const pubkey = receipt.signer.pubkey; // "ed25519:base64..."
  const bare = pubkey.startsWith('ed25519:') ? pubkey.slice('ed25519:'.length) : pubkey;
  return { publicKey: bare, secretKey: seed };
}

module.exports = { generateKeypair, sign, contentHash, loadOrCreateKey };
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd plugins/claude-code && node --test tests/signet.test.cjs
```

Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add plugins/claude-code/lib/signet.cjs plugins/claude-code/tests/signet.test.cjs
git commit -m "feat(plugin): add WASM wrapper lib/signet.cjs with tests"
```

---

### Task 4: Implement lib/audit.cjs (Hash-Chained JSONL)

**Files:**
- Create: `plugins/claude-code/lib/audit.cjs`
- Create: `plugins/claude-code/tests/audit.test.cjs`

- [ ] **Step 1: Write failing tests**

Write `plugins/claude-code/tests/audit.test.cjs`:
```js
'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const audit = require('../lib/audit.cjs');

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signet-audit-'));
}

function fakeReceipt(tool) {
  return {
    v: 1,
    id: 'rec_test_' + Math.random().toString(36).slice(2),
    action: { tool, params: {}, params_hash: '', target: 'test', transport: 'stdio' },
    signer: { pubkey: 'ed25519:fake', name: 'test', owner: '' },
    ts: new Date().toISOString(),
    nonce: 'nonce_test',
    sig: 'ed25519:fakesig',
  };
}

describe('audit.cjs', () => {
  it('append creates audit directory and file', () => {
    const tmpDir = makeTmpDir();
    const receipt = fakeReceipt('Bash');
    audit.append(tmpDir, receipt);

    const auditDir = path.join(tmpDir, 'audit');
    assert.ok(fs.existsSync(auditDir), 'audit dir should exist');

    const files = fs.readdirSync(auditDir);
    assert.equal(files.length, 1);
    assert.ok(files[0].endsWith('.jsonl'));
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('append writes valid JSONL record with hash chain fields', () => {
    const tmpDir = makeTmpDir();
    audit.append(tmpDir, fakeReceipt('Bash'));

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const line = fs.readFileSync(path.join(auditDir, file), 'utf8').trim();
    const record = JSON.parse(line);

    assert.ok(record.receipt, 'should have receipt');
    assert.ok(record.prev_hash, 'should have prev_hash');
    assert.ok(record.record_hash, 'should have record_hash');
    assert.equal(record.prev_hash, 'sha256:genesis');
    assert.ok(record.record_hash.startsWith('sha256:'));
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('append chains hashes across records', () => {
    const tmpDir = makeTmpDir();
    audit.append(tmpDir, fakeReceipt('Bash'));
    audit.append(tmpDir, fakeReceipt('Read'));

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const lines = fs.readFileSync(path.join(auditDir, file), 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);

    const rec1 = JSON.parse(lines[0]);
    const rec2 = JSON.parse(lines[1]);

    // Second record's prev_hash should equal first record's record_hash
    assert.equal(rec2.prev_hash, rec1.record_hash);
    // Hashes should be different
    assert.notEqual(rec1.record_hash, rec2.record_hash);
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('record_hash is deterministic (same input = same hash)', () => {
    const tmpDir1 = makeTmpDir();
    const tmpDir2 = makeTmpDir();
    const receipt = fakeReceipt('Bash');
    // Force same nonce/id for determinism
    receipt.id = 'rec_fixed';
    receipt.nonce = 'nonce_fixed';
    receipt.ts = '2026-04-05T00:00:00.000Z';

    audit.append(tmpDir1, receipt);
    audit.append(tmpDir2, receipt);

    const read = (dir) => {
      const f = fs.readdirSync(path.join(dir, 'audit'))[0];
      return JSON.parse(fs.readFileSync(path.join(dir, 'audit', f), 'utf8').trim());
    };

    assert.equal(read(tmpDir1).record_hash, read(tmpDir2).record_hash);
    fs.rmSync(tmpDir1, { recursive: true });
    fs.rmSync(tmpDir2, { recursive: true });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd plugins/claude-code && node --test tests/audit.test.cjs
```

Expected: FAIL — `Cannot find module '../lib/audit.cjs'`

- [ ] **Step 3: Implement lib/audit.cjs**

Write `plugins/claude-code/lib/audit.cjs`:
```js
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const signet = require('./signet.cjs');

const GENESIS_HASH = 'sha256:genesis';

/**
 * Append a signed receipt to the hash-chained audit log.
 * Compatible with signet CLI's `signet audit` and `signet verify --chain`.
 *
 * @param {string} signetDir - path to ~/.signet (or test dir)
 * @param {object} receipt - signed receipt object
 */
function append(signetDir, receipt) {
  const auditDir = path.join(signetDir, 'audit');
  fs.mkdirSync(auditDir, { recursive: true });

  // Determine filename from receipt timestamp
  const ts = receipt.ts || receipt.ts_request || new Date().toISOString();
  const date = ts.slice(0, 10); // YYYY-MM-DD
  const filepath = path.join(auditDir, date + '.jsonl');

  // Get prev_hash from last line of file
  const prevHash = lastRecordHash(filepath, auditDir);

  // Compute record_hash = sha256(JCS({ prev_hash, receipt }))
  // This matches Rust's audit::compute_record_hash exactly
  const recordHash = signet.contentHash({ prev_hash: prevHash, receipt });

  const record = {
    receipt,
    prev_hash: prevHash,
    record_hash: recordHash,
  };

  fs.appendFileSync(filepath, JSON.stringify(record) + '\n');
}

/**
 * Get the record_hash of the last record in a file, or check previous day files.
 */
function lastRecordHash(filepath, auditDir) {
  if (fs.existsSync(filepath)) {
    const content = fs.readFileSync(filepath, 'utf8');
    const lines = content.trim().split('\n').filter(l => l.trim());
    if (lines.length > 0) {
      const last = JSON.parse(lines[lines.length - 1]);
      return last.record_hash;
    }
  }

  // Check previous day files (sorted descending)
  if (fs.existsSync(auditDir)) {
    const files = fs.readdirSync(auditDir)
      .filter(f => f.endsWith('.jsonl'))
      .sort()
      .reverse();
    for (const file of files) {
      const fullPath = path.join(auditDir, file);
      if (fullPath === filepath) continue;
      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.trim().split('\n').filter(l => l.trim());
      if (lines.length > 0) {
        const last = JSON.parse(lines[lines.length - 1]);
        return last.record_hash;
      }
    }
  }

  return GENESIS_HASH;
}

module.exports = { append };
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd plugins/claude-code && node --test tests/audit.test.cjs
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add plugins/claude-code/lib/audit.cjs plugins/claude-code/tests/audit.test.cjs
git commit -m "feat(plugin): add hash-chained audit log lib/audit.cjs with tests"
```

---

### Task 5: Implement bin/sign.cjs (Hook Entry Point)

**Files:**
- Create: `plugins/claude-code/bin/sign.cjs`
- Create: `plugins/claude-code/tests/sign-hook.test.cjs`

- [ ] **Step 1: Write failing tests**

Write `plugins/claude-code/tests/sign-hook.test.cjs`:
```js
'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const SIGN_CJS = path.join(__dirname, '..', 'bin', 'sign.cjs');

function runHook(stdinObj, env) {
  const input = JSON.stringify(stdinObj);
  const result = execFileSync('node', [SIGN_CJS], {
    input,
    env: { ...process.env, ...env },
    timeout: 10000,
  });
  return result.toString();
}

describe('bin/sign.cjs hook', () => {
  it('signs a tool call from stdin JSON', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    runHook(
      { tool_name: 'Bash', tool_input: { command: 'ls -la' } },
      { SIGNET_HOME: tmpDir },
    );

    // Check audit log was written
    const auditDir = path.join(tmpDir, 'audit');
    assert.ok(fs.existsSync(auditDir), 'audit dir should exist');
    const files = fs.readdirSync(auditDir);
    assert.equal(files.length, 1);

    const line = fs.readFileSync(path.join(auditDir, files[0]), 'utf8').trim();
    const record = JSON.parse(line);
    assert.equal(record.receipt.action.tool, 'Bash');
    assert.equal(record.receipt.signer.name, 'claude-agent');
    assert.ok(record.receipt.sig.startsWith('ed25519:'));
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('auto-generates key on first run', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    runHook(
      { tool_name: 'Read', tool_input: { file_path: '/tmp/test' } },
      { SIGNET_HOME: tmpDir },
    );
    const keyPath = path.join(tmpDir, 'keys', 'claude-agent.key');
    assert.ok(fs.existsSync(keyPath), 'key should be auto-generated');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('chains hashes across multiple calls', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    const env = { SIGNET_HOME: tmpDir };
    runHook({ tool_name: 'Bash', tool_input: { command: 'echo 1' } }, env);
    runHook({ tool_name: 'Read', tool_input: { file_path: '/tmp/a' } }, env);

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const lines = fs.readFileSync(path.join(auditDir, file), 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);

    const rec1 = JSON.parse(lines[0]);
    const rec2 = JSON.parse(lines[1]);
    assert.equal(rec2.prev_hash, rec1.record_hash);
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('exits 0 on invalid stdin (no crash)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    // Should not throw — exits 0 even on bad input
    const result = execFileSync('node', [SIGN_CJS], {
      input: 'not json',
      env: { ...process.env, SIGNET_HOME: tmpDir },
      timeout: 10000,
    });
    fs.rmSync(tmpDir, { recursive: true });
    // If we got here, it didn't crash. Pass.
  });

  it('exits 0 on empty stdin', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    const result = execFileSync('node', [SIGN_CJS], {
      input: '',
      env: { ...process.env, SIGNET_HOME: tmpDir },
      timeout: 10000,
    });
    fs.rmSync(tmpDir, { recursive: true });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd plugins/claude-code && node --test tests/sign-hook.test.cjs
```

Expected: FAIL — `Cannot find module '../bin/sign.cjs'` or similar.

- [ ] **Step 3: Implement bin/sign.cjs**

Write `plugins/claude-code/bin/sign.cjs`:
```js
#!/usr/bin/env node
'use strict';

// Signet PostToolUse hook — signs every tool call.
// Input: stdin JSON { tool_name, tool_input, tool_response }
// Output: none (audit log written to ~/.signet/audit/)
// On any error: stderr warning, exit 0. Never blocks tool calls.

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function main() {
  const signetDir = process.env.SIGNET_HOME
    || path.join(os.homedir(), '.signet');
  const keyPath = path.join(signetDir, 'keys', 'claude-agent.key');

  // Read stdin
  let raw;
  try {
    raw = fs.readFileSync(0, 'utf8');
  } catch {
    return; // No stdin, nothing to sign
  }
  if (!raw || !raw.trim()) return;

  // Parse stdin JSON
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    process.stderr.write('signet: failed to parse stdin JSON\n');
    return;
  }

  const toolName = input.tool_name || 'unknown';
  const toolInput = input.tool_input || {};

  // Load WASM wrapper (lazy, so we don't pay cost if stdin is empty)
  const signet = require('../lib/signet.cjs');
  const audit = require('../lib/audit.cjs');

  // Load or create key
  let key;
  try {
    key = signet.loadOrCreateKey(keyPath);
  } catch (err) {
    process.stderr.write('signet: ' + err.message + '\n');
    return;
  }

  // Sign the action
  const action = {
    tool: toolName,
    params: toolInput,
    params_hash: '',
    target: 'claude-code://local',
    transport: 'stdio',
  };

  let receipt;
  try {
    receipt = signet.sign(key.secretKey, action, 'claude-agent');
  } catch (err) {
    process.stderr.write('signet: signing failed: ' + err.message + '\n');
    return;
  }

  // Append to audit log
  try {
    audit.append(signetDir, receipt);
  } catch (err) {
    process.stderr.write('signet: audit append failed: ' + err.message + '\n');
  }
}

try {
  main();
} catch (err) {
  process.stderr.write('signet: unexpected error: ' + err.message + '\n');
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd plugins/claude-code && node --test tests/sign-hook.test.cjs
```

Expected: All 5 tests PASS.

- [ ] **Step 5: Run all tests together**

```bash
cd plugins/claude-code && node --test tests/
```

Expected: All 15 tests PASS (6 signet + 4 audit + 5 hook).

- [ ] **Step 6: Commit**

```bash
git add plugins/claude-code/bin/sign.cjs plugins/claude-code/tests/sign-hook.test.cjs
git commit -m "feat(plugin): add PostToolUse hook entry point bin/sign.cjs with tests"
```

---

### Task 6: Add README + Final Integration Test

**Files:**
- Create: `plugins/claude-code/README.md`

- [ ] **Step 1: Write README**

Write `plugins/claude-code/README.md`:
```markdown
# Signet Claude Code Plugin

Cryptographic signing for every tool call in Claude Code. Ed25519 receipts + hash-chained audit log.

## Install

```
claude plugin add signet
```

Or clone and register manually:
```bash
git clone https://github.com/Prismer-AI/signet.git
cd signet/plugins/claude-code
claude plugin add .
```

## What It Does

Every tool call Claude Code makes is automatically:
1. **Signed** with an Ed25519 key (auto-generated on first use)
2. **Logged** to a hash-chained audit trail at `~/.signet/audit/`

No configuration needed. Signing starts immediately after installation.

## Audit

View raw logs:
```bash
cat ~/.signet/audit/$(date +%Y-%m-%d).jsonl | jq '.receipt.action.tool'
```

With [signet CLI](https://github.com/Prismer-AI/signet) (optional):
```bash
signet audit --since 1h
signet audit --verify   # verify hash chain integrity
```

## Key Management

- Keys stored at `~/.signet/keys/claude-agent.key` (unencrypted, 0600 permissions)
- Auto-generated on first tool call
- Shared with signet CLI if installed

## How It Works

A PostToolUse hook runs after every tool call, reading the tool name and
input from stdin. The hook signs the action with the agent's Ed25519 key
using an embedded WASM module (no Rust or native dependencies needed),
then appends the signed receipt to the daily audit log.

## License

Apache-2.0 OR MIT
```

- [ ] **Step 2: Run full test suite one final time**

```bash
cd plugins/claude-code && node --test tests/
```

Expected: All 15 tests PASS.

- [ ] **Step 3: Commit README**

```bash
git add plugins/claude-code/README.md
git commit -m "docs(plugin): add Claude Code plugin README"
```

---

### Task 7: Update Root package.json Workspaces + Spec Commit

**Files:**
- Modify: `package.json` (root)
- Modify: `docs/superpowers/specs/2026-04-05-claude-code-plugin-design.md` (already exists)

- [ ] **Step 1: Update root package.json to include plugin in workspaces (if needed)**

The plugin has zero npm deps and `"private": true`, so it does not need to be in npm workspaces. Skip this if the monorepo workspace config would cause issues. Only add it if `npm install` from root needs to resolve it.

Check: `cat package.json` at root. If workspaces is `["packages/*"]`, no change needed — the plugin is in `plugins/`, not `packages/`.

- [ ] **Step 2: Commit spec document**

```bash
git add docs/superpowers/specs/2026-04-05-claude-code-plugin-design.md
git commit -m "docs: add Claude Code plugin design spec"
```

- [ ] **Step 3: Final verification**

```bash
# All plugin tests
cd plugins/claude-code && node --test tests/

# Existing Rust tests still pass
cd ../.. && cargo test --workspace

# Existing TS tests still pass
cd packages/signet-core && npm test
```

Expected: All green across Rust, TS, and plugin tests.
