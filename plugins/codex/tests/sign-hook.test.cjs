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
    assert.equal(record.receipt.signer.name, 'codex-agent');
    assert.ok(record.receipt.sig.startsWith('ed25519:'));
    assert.ok(record.receipt.action.params_hash.startsWith('sha256:'), 'params_hash should be computed');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('includes session_id, call_id, and response_hash in signed action', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    runHook(
      {
        tool_name: 'Bash',
        tool_input: { command: 'echo hello' },
        session_id: 'sess_abc123',
        tool_use_id: 'toolu_xyz789',
        tool_response: { stdout: 'hello\n' },
      },
      { SIGNET_HOME: tmpDir },
    );

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const line = fs.readFileSync(path.join(auditDir, file), 'utf8').trim();
    const record = JSON.parse(line);
    const action = record.receipt.action;
    assert.equal(action.session, 'sess_abc123');
    assert.equal(action.call_id, 'toolu_xyz789');
    assert.ok(action.response_hash.startsWith('sha256:'), 'response_hash should be computed');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('stores tool_response in audit record meta (unsigned)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    runHook(
      {
        tool_name: 'Read',
        tool_input: { file_path: '/tmp/test' },
        tool_response: { content: 'file contents' },
      },
      { SIGNET_HOME: tmpDir },
    );

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const line = fs.readFileSync(path.join(auditDir, file), 'utf8').trim();
    const record = JSON.parse(line);
    assert.deepEqual(record.meta.tool_response, { content: 'file contents' });
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('stores cwd and transcript_path in audit meta', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    runHook(
      {
        tool_name: 'Bash',
        tool_input: { command: 'pwd' },
        cwd: '/home/user/project',
        transcript_path: '/home/user/.claude/sess.jsonl',
      },
      { SIGNET_HOME: tmpDir },
    );

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const line = fs.readFileSync(path.join(auditDir, file), 'utf8').trim();
    const record = JSON.parse(line);
    assert.equal(record.meta.cwd, '/home/user/project');
    assert.equal(record.meta.transcript_path, '/home/user/.claude/sess.jsonl');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('response_hash matches expected hash of tool_response', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    const toolResponse = { stdout: 'hello\n' };
    runHook(
      {
        tool_name: 'Bash',
        tool_input: { command: 'echo hello' },
        tool_response: toolResponse,
      },
      { SIGNET_HOME: tmpDir },
    );

    const signet = require('../lib/signet.cjs');
    const expectedHash = signet.contentHash(toolResponse);

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const line = fs.readFileSync(path.join(auditDir, file), 'utf8').trim();
    const record = JSON.parse(line);
    assert.equal(record.receipt.action.response_hash, expectedHash);
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('truncates large tool_response in meta', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    const largeResponse = { data: 'x'.repeat(100 * 1024) }; // > 64KB
    runHook(
      {
        tool_name: 'Read',
        tool_input: { file_path: '/tmp/big' },
        tool_response: largeResponse,
      },
      { SIGNET_HOME: tmpDir },
    );

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const line = fs.readFileSync(path.join(auditDir, file), 'utf8').trim();
    const record = JSON.parse(line);
    assert.equal(record.meta.tool_response_truncated, true);
    assert.equal(typeof record.meta.tool_response_size, 'number');
    assert.equal(record.meta.tool_response, undefined);
    // response_hash is still computed from the full response
    assert.ok(record.receipt.action.response_hash.startsWith('sha256:'));
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('omits session/call_id/response_hash when not provided', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    runHook(
      { tool_name: 'Bash', tool_input: { command: 'ls' } },
      { SIGNET_HOME: tmpDir },
    );

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const line = fs.readFileSync(path.join(auditDir, file), 'utf8').trim();
    const record = JSON.parse(line);
    assert.equal(record.receipt.action.session, undefined);
    assert.equal(record.receipt.action.call_id, undefined);
    assert.equal(record.receipt.action.response_hash, undefined);
    assert.equal(record.meta, undefined);
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('auto-generates key on first run', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-hook-'));
    runHook(
      { tool_name: 'Read', tool_input: { file_path: '/tmp/test' } },
      { SIGNET_HOME: tmpDir },
    );
    const keyPath = path.join(tmpDir, 'keys', 'codex-agent.key');
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
