import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateKeypair, sign, verify, type SignetAction,
  signDelegation, verifyDelegation, signAuthorized, verifyAuthorized,
  type Scope, type DelegationToken,
} from '../src/index.js';

describe('@signet-auth/core', () => {
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

describe('delegation chain', () => {
  const testAction: SignetAction = {
    tool: 'Bash',
    params: { cmd: 'ls' },
    params_hash: '',
    target: 'mcp://test',
    transport: 'stdio',
  };

  const testScope: Scope = {
    tools: ['Bash', 'Read'],
    targets: ['mcp://test'],
    max_depth: 0,
  };

  it('signDelegation produces valid token', () => {
    const root = generateKeypair();
    const agent = generateKeypair();

    const token = signDelegation(root.secretKey, 'alice', agent.publicKey, 'bot', testScope);
    assert.strictEqual(token.v, 1);
    assert(token.id.startsWith('del_'));
    assert(token.sig.startsWith('ed25519:'));
    assert.strictEqual(token.delegator.name, 'alice');
    assert.strictEqual(token.delegate.name, 'bot');
    assert.deepStrictEqual(token.scope.tools, ['Bash', 'Read']);
  });

  it('verifyDelegation roundtrip', () => {
    const root = generateKeypair();
    const agent = generateKeypair();

    const token = signDelegation(root.secretKey, 'alice', agent.publicKey, 'bot', testScope);
    assert.strictEqual(verifyDelegation(token), true);
  });

  it('verifyDelegation rejects tampered token', () => {
    const root = generateKeypair();
    const agent = generateKeypair();

    const token = signDelegation(root.secretKey, 'alice', agent.publicKey, 'bot', testScope);
    const tampered = { ...token, delegate: { ...token.delegate, name: 'evil' } };
    assert.strictEqual(verifyDelegation(tampered), false);
  });

  it('signAuthorized produces v4 receipt', () => {
    const root = generateKeypair();
    const agent = generateKeypair();

    const token = signDelegation(root.secretKey, 'alice', agent.publicKey, 'bot', testScope);
    const receipt = signAuthorized(agent.secretKey, testAction, 'bot', [token]);

    assert.strictEqual(receipt.v, 4);
    assert(receipt.id.startsWith('rec_'));
    assert(receipt.authorization !== undefined);
    assert(receipt.authorization.chain.length === 1);
    assert(receipt.authorization.chain_hash.startsWith('sha256:'));
    assert.strictEqual(receipt.signer.owner, 'alice');
  });

  it('verifyAuthorized roundtrip', () => {
    const root = generateKeypair();
    const agent = generateKeypair();

    const token = signDelegation(root.secretKey, 'alice', agent.publicKey, 'bot', testScope);
    const receipt = signAuthorized(agent.secretKey, testAction, 'bot', [token]);

    const scope = verifyAuthorized(receipt, [root.publicKey]);
    assert.deepStrictEqual(scope.tools, ['Bash', 'Read']);
    assert.deepStrictEqual(scope.targets, ['mcp://test']);
  });

  it('verifyAuthorized rejects wrong root', () => {
    const root = generateKeypair();
    const wrongRoot = generateKeypair();
    const agent = generateKeypair();

    const token = signDelegation(root.secretKey, 'alice', agent.publicKey, 'bot', testScope);
    const receipt = signAuthorized(agent.secretKey, testAction, 'bot', [token]);

    assert.throws(() => verifyAuthorized(receipt, [wrongRoot.publicKey]));
  });
});
