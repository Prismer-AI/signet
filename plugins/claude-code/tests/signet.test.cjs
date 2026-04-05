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
    assert.equal(hash, signet.contentHash({ hello: 'world' }));
  });

  it('loadOrCreateKey creates key file when missing', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signet-test-'));
    const keyPath = path.join(tmpDir, 'keys', 'claude-agent.key');
    const result = signet.loadOrCreateKey(keyPath);
    assert.ok(result.publicKey);
    assert.ok(result.secretKey);
    assert.ok(fs.existsSync(keyPath), 'key file should exist');
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
    const kp1 = signet.loadOrCreateKey(keyPath);
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
    fs.writeFileSync(keyPath, JSON.stringify({
      v: 1, algorithm: 'ed25519', name: 'claude-agent',
      kdf: 'argon2id', ciphertext: 'fake'
    }));
    assert.throws(() => signet.loadOrCreateKey(keyPath), /encrypted/i);
    fs.rmSync(tmpDir, { recursive: true });
  });
});
