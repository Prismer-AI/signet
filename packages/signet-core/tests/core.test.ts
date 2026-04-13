import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateKeypair, sign, verify, type SignetAction,
  signDelegation, verifyDelegation, signAuthorized, verifyAuthorized,
  parsePolicyYaml, evaluatePolicy, signWithPolicy, computePolicyHash,
  type Scope, type DelegationToken, type PolicyEvalResult,
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

describe('policy engine', () => {
  const testAction: SignetAction = {
    tool: 'Read',
    params: { path: '/tmp' },
    params_hash: '',
    target: 'mcp://local',
    transport: 'stdio',
  };

  const allowPolicyYaml = `
version: 1
name: test-allow
rules:
  - id: allow-read
    match:
      tool: Read
    action: allow
`;

  const denyPolicyYaml = `
version: 1
name: test-deny
default_action: deny
rules: []
`;

  it('parsePolicyYaml parses and returns policy object', () => {
    const policy = parsePolicyYaml(allowPolicyYaml);
    assert.strictEqual(policy.name, 'test-allow');
    assert.strictEqual(policy.version, 1);
  });

  it('computePolicyHash returns sha256 hash', () => {
    const policy = parsePolicyYaml(allowPolicyYaml);
    const hash = computePolicyHash(policy);
    assert.ok(hash.startsWith('sha256:'));
    assert.strictEqual(hash.length, 71);
  });

  it('computePolicyHash is deterministic', () => {
    const policy = parsePolicyYaml(allowPolicyYaml);
    assert.strictEqual(computePolicyHash(policy), computePolicyHash(policy));
  });

  it('evaluatePolicy returns allow for matching rule', () => {
    const policy = parsePolicyYaml(allowPolicyYaml);
    const result = evaluatePolicy(testAction, 'agent', policy);
    assert.strictEqual(result.decision, 'allow');
    assert.ok(result.matched_rules.includes('allow-read'));
  });

  it('evaluatePolicy returns deny for deny-default policy', () => {
    const policy = parsePolicyYaml(denyPolicyYaml);
    const result = evaluatePolicy(testAction, 'agent', policy);
    assert.strictEqual(result.decision, 'deny');
  });

  it('signWithPolicy produces receipt with policy attestation and eval', () => {
    const kp = generateKeypair();
    const policy = parsePolicyYaml(allowPolicyYaml);
    const { receipt, eval: evalResult } = signWithPolicy(kp.secretKey, testAction, 'agent', 'owner', policy);
    assert.strictEqual(receipt.v, 1);
    assert.ok(receipt.policy);
    assert.strictEqual(receipt.policy.policy_name, 'test-allow');
    assert.strictEqual(receipt.policy.decision, 'allow');
    assert.ok(receipt.policy.policy_hash.startsWith('sha256:'));
    assert.strictEqual(evalResult.decision, 'allow');
    assert.ok(evalResult.matched_rules.includes('allow-read'));
  });

  it('signWithPolicy receipt is verifiable', () => {
    const kp = generateKeypair();
    const policy = parsePolicyYaml(allowPolicyYaml);
    const { receipt } = signWithPolicy(kp.secretKey, testAction, 'agent', 'owner', policy);
    assert.strictEqual(verify(receipt, kp.publicKey), true);
  });

  it('signWithPolicy throws on deny policy', () => {
    const kp = generateKeypair();
    const policy = parsePolicyYaml(denyPolicyYaml);
    assert.throws(
      () => signWithPolicy(kp.secretKey, testAction, 'agent', 'owner', policy),
      /policy violation/i,
    );
  });

  it('signWithPolicy throws on require_approval policy', () => {
    const kp = generateKeypair();
    const approvalPolicy = parsePolicyYaml(`
version: 1
name: test-approval
rules:
  - id: needs-approval
    match:
      tool: Read
    action: require_approval
    reason: needs human approval
`);
    assert.throws(
      () => signWithPolicy(kp.secretKey, testAction, 'agent', 'owner', approvalPolicy),
      /requires.*approval/i,
    );
  });

  it('signWithPolicy tampered attestation fails verify', () => {
    const kp = generateKeypair();
    const policy = parsePolicyYaml(allowPolicyYaml);
    const { receipt } = signWithPolicy(kp.secretKey, testAction, 'agent', 'owner', policy);
    receipt.policy.policy_name = 'forged';
    assert.strictEqual(verify(receipt, kp.publicKey), false);
  });

  it('parsePolicyYaml throws on invalid YAML', () => {
    assert.throws(
      () => parsePolicyYaml('not: valid: yaml: [[['),
    );
  });
});

describe('signed trace correlation', () => {
  it('trace_id is included in signed receipt', () => {
    const kp = generateKeypair();
    const action: SignetAction = {
      tool: 'Bash',
      params: { cmd: 'ls' },
      params_hash: '',
      target: 'mcp://local',
      transport: 'stdio',
      trace_id: 'tr_test123',
    };
    const receipt = sign(kp.secretKey, action, 'agent', 'owner');
    assert.strictEqual(receipt.action.trace_id, 'tr_test123');
    assert.strictEqual(verify(receipt, kp.publicKey), true);
  });

  it('parent_receipt_id is included in signed receipt', () => {
    const kp = generateKeypair();
    const action: SignetAction = {
      tool: 'Write',
      params: {},
      params_hash: '',
      target: 'mcp://local',
      transport: 'stdio',
      parent_receipt_id: 'rec_parent',
    };
    const receipt = sign(kp.secretKey, action, 'agent', 'owner');
    assert.strictEqual(receipt.action.parent_receipt_id, 'rec_parent');
    assert.strictEqual(verify(receipt, kp.publicKey), true);
  });

  it('trace_id tampering invalidates signature', () => {
    const kp = generateKeypair();
    const action: SignetAction = {
      tool: 'Bash',
      params: {},
      params_hash: '',
      target: 'mcp://local',
      transport: 'stdio',
      trace_id: 'tr_legit',
    };
    const receipt = sign(kp.secretKey, action, 'agent', 'owner');
    receipt.action.trace_id = 'tr_forged';
    assert.strictEqual(verify(receipt, kp.publicKey), false);
  });

  it('trace fields absent when not set', () => {
    const kp = generateKeypair();
    const action: SignetAction = {
      tool: 'Read',
      params: {},
      params_hash: '',
      target: 'mcp://local',
      transport: 'stdio',
    };
    const receipt = sign(kp.secretKey, action, 'agent', 'owner');
    assert.strictEqual(receipt.action.trace_id, undefined);
    assert.strictEqual(receipt.action.parent_receipt_id, undefined);
    assert.strictEqual(verify(receipt, kp.publicKey), true);
  });

  it('workflow start + child calls with trace chain', () => {
    const kp = generateKeypair();

    // Workflow start
    const startReceipt = sign(kp.secretKey, {
      tool: '_workflow_start',
      params: { skill: 'create-flask-app' },
      params_hash: '',
      target: 'mcp://local',
      transport: 'stdio',
      trace_id: 'tr_wf001',
    }, 'agent', 'owner');

    // Child 1 references start
    const child1 = sign(kp.secretKey, {
      tool: 'Bash',
      params: { cmd: 'pip install flask' },
      params_hash: '',
      target: 'mcp://local',
      transport: 'stdio',
      trace_id: 'tr_wf001',
      parent_receipt_id: startReceipt.id,
    }, 'agent', 'owner');

    // Child 2 references child 1
    const child2 = sign(kp.secretKey, {
      tool: 'Write',
      params: { path: 'app.py' },
      params_hash: '',
      target: 'mcp://local',
      transport: 'stdio',
      trace_id: 'tr_wf001',
      parent_receipt_id: child1.id,
    }, 'agent', 'owner');

    // All verifiable
    assert.strictEqual(verify(startReceipt, kp.publicKey), true);
    assert.strictEqual(verify(child1, kp.publicKey), true);
    assert.strictEqual(verify(child2, kp.publicKey), true);

    // Chain intact
    assert.strictEqual(child1.action.trace_id, 'tr_wf001');
    assert.strictEqual(child1.action.parent_receipt_id, startReceipt.id);
    assert.strictEqual(child2.action.parent_receipt_id, child1.id);
  });
});
