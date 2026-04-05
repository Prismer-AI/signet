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

    const auditDir = path.join(tmpDir, 'audit');
    assert.ok(fs.existsSync(auditDir), 'audit dir should exist');
    const files = fs.readdirSync(auditDir);
    assert.equal(files.length, 1);

    const line = fs.readFileSync(path.join(auditDir, files[0]), 'utf8').trim();
    const record = JSON.parse(line);
    assert.equal(record.receipt.action.tool, 'Bash');
    assert.equal(record.receipt.signer.name, 'claude-agent');
    assert.ok(record.receipt.sig.startsWith('ed25519:'));
    assert.ok(record.receipt.action.params_hash.startsWith('sha256:'), 'params_hash should be computed');
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
    const result = execFileSync('node', [SIGN_CJS], {
      input: 'not json',
      env: { ...process.env, SIGNET_HOME: tmpDir },
      timeout: 10000,
    });
    fs.rmSync(tmpDir, { recursive: true });
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
