import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateKeypair, sign, verify, type SignetAction } from '../src/index.js';

describe('@signet/core', () => {
  const testAction: SignetAction = {
    tool: 'github_create_issue',
    params: { title: 'fix bug', body: 'details' },
    params_hash: '',
    target: 'mcp://github.local',
    transport: 'stdio',
  };

  it('generateKeypair returns secretKey and publicKey', () => {
    const kp = generateKeypair();
    assert(kp.secretKey, 'secretKey should be non-empty');
    assert(kp.publicKey, 'publicKey should be non-empty');
    assert(typeof kp.secretKey === 'string');
    assert(typeof kp.publicKey === 'string');
  });

  it('sign produces receipt with all fields', () => {
    const kp = generateKeypair();
    const receipt = sign(kp.secretKey, testAction, 'test-agent', 'owner');
    assert.strictEqual(receipt.v, 1);
    assert(receipt.id.startsWith('rec_'));
    assert(receipt.sig.startsWith('ed25519:'));
    assert(receipt.nonce.startsWith('rnd_'));
    assert.strictEqual(receipt.signer.name, 'test-agent');
    assert.strictEqual(receipt.action.tool, 'github_create_issue');
  });

  it('sign then verify roundtrip succeeds', () => {
    const kp = generateKeypair();
    const receipt = sign(kp.secretKey, testAction, 'agent', 'owner');
    assert.strictEqual(verify(receipt, kp.publicKey), true);
  });

  it('verify with wrong key returns false', () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const receipt = sign(kp1.secretKey, testAction, 'agent', 'owner');
    assert.strictEqual(verify(receipt, kp2.publicKey), false);
  });

  it('verify tampered receipt returns false', () => {
    const kp = generateKeypair();
    const receipt = sign(kp.secretKey, testAction, 'agent', 'owner');
    const tampered = { ...receipt, action: { ...receipt.action, tool: 'evil_tool' } };
    assert.strictEqual(verify(tampered, kp.publicKey), false);
  });

  it('params_hash is computed automatically', () => {
    const kp = generateKeypair();
    const receipt = sign(kp.secretKey, testAction, 'agent', 'owner');
    assert(receipt.action.params_hash.startsWith('sha256:'));
    assert(receipt.action.params_hash.length > 10);
  });
});
