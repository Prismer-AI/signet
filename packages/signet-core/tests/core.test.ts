import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateKeypair, sign, verify, type SignetAction,
  signDelegation, verifyDelegation, signAuthorized, verifyAuthorized,
  parsePolicyYaml, evaluatePolicy, signWithPolicy, computePolicyHash,
  signWithExpiration, verifyAllowExpired,
  signCompound, signBilateral, verifyBilateral, verifyAny, contentHash,
  verifyBilateralWithOptions, verifyBilateralWithOptionsDetailed,
  type Scope, type DelegationToken, type PolicyEvalResult,
  type CompoundReceipt, type BilateralReceipt, type BilateralVerifyOutcome,
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

describe('receipt expiration', () => {
  const testAction: SignetAction = {
    tool: 'Read',
    params: {},
    params_hash: '',
    target: 'mcp://local',
    transport: 'stdio',
  };

  it('signWithExpiration produces receipt with exp field', () => {
    const kp = generateKeypair();
    const future = new Date(Date.now() + 3600000).toISOString();
    const receipt = signWithExpiration(kp.secretKey, testAction, 'agent', 'owner', future);
    assert.strictEqual(receipt.exp, future);
    assert.strictEqual(verify(receipt, kp.publicKey), true);
  });

  it('sign without expiration has no exp field', () => {
    const kp = generateKeypair();
    const receipt = sign(kp.secretKey, testAction, 'agent', 'owner');
    assert.strictEqual(receipt.exp, undefined);
  });

  it('tampered expiration fails verification', () => {
    const kp = generateKeypair();
    const future = new Date(Date.now() + 3600000).toISOString();
    const receipt = signWithExpiration(kp.secretKey, testAction, 'agent', 'owner', future);
    receipt.exp = new Date(Date.now() + 86400000 * 365).toISOString();
    assert.strictEqual(verify(receipt, kp.publicKey), false);
  });

  it('verifyAllowExpired accepts expired receipts', () => {
    const kp = generateKeypair();
    const past = new Date(Date.now() - 3600000).toISOString();
    const receipt = signWithExpiration(kp.secretKey, testAction, 'agent', 'owner', past);
    // verify would reject (expired), but verifyAllowExpired accepts
    assert.strictEqual(verifyAllowExpired(receipt, kp.publicKey), true);
  });

  it('verifyAllowExpired still rejects tampered signatures', () => {
    const kp = generateKeypair();
    const past = new Date(Date.now() - 3600000).toISOString();
    const receipt = signWithExpiration(kp.secretKey, testAction, 'agent', 'owner', past);
    receipt.action.tool = 'evil';
    assert.strictEqual(verifyAllowExpired(receipt, kp.publicKey), false);
  });
});

// ─── v2 Compound receipts ────────────────────────────────────────────────────

describe('v2 compound receipts', () => {
  const action: SignetAction = {
    tool: 'web_search',
    params: { q: 'test' },
    params_hash: '',
    target: 'mcp://search',
    transport: 'stdio',
  };

  it('signCompound produces v2 receipt with response', () => {
    const kp = generateKeypair();
    const ts = new Date().toISOString();
    const receipt = signCompound(
      kp.secretKey, action, { result: 'data' }, 'agent', 'owner', ts, ts,
    );
    assert.strictEqual(receipt.v, 2);
    assert(receipt.id.startsWith('rec_'));
    assert(receipt.sig.startsWith('ed25519:'));
    assert.strictEqual(receipt.signer.name, 'agent');
    assert.strictEqual(receipt.action.tool, 'web_search');
    assert(receipt.response.content_hash.startsWith('sha256:'));
  });

  it('verifyAny accepts v2 compound receipts', () => {
    const kp = generateKeypair();
    const ts = new Date().toISOString();
    const receipt = signCompound(
      kp.secretKey, action, { result: 'data' }, 'agent', 'owner', ts, ts,
    );
    assert.strictEqual(verifyAny(JSON.stringify(receipt), kp.publicKey), true);
  });

  it('v2 tampered action invalidates signature', () => {
    const kp = generateKeypair();
    const ts = new Date().toISOString();
    const receipt = signCompound(
      kp.secretKey, action, { result: 'data' }, 'agent', 'owner', ts, ts,
    );
    receipt.action.tool = 'evil';
    assert.strictEqual(verifyAny(JSON.stringify(receipt), kp.publicKey), false);
  });

  it('v2 tampered response invalidates signature', () => {
    const kp = generateKeypair();
    const ts = new Date().toISOString();
    const receipt = signCompound(
      kp.secretKey, action, { result: 'data' }, 'agent', 'owner', ts, ts,
    );
    receipt.response.content_hash = 'sha256:0000';
    assert.strictEqual(verifyAny(JSON.stringify(receipt), kp.publicKey), false);
  });
});

// ─── v3 Bilateral receipts ───────────────────────────────────────────────────

describe('v3 bilateral receipts', () => {
  const action: SignetAction = {
    tool: 'create_issue',
    params: { title: 'bug' },
    params_hash: '',
    target: 'mcp://github',
    transport: 'stdio',
  };

  it('signBilateral wraps an agent receipt with a server signature', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const ts = new Date().toISOString();

    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), { ok: true }, 'github-mcp', ts,
    );
    assert.strictEqual(bilateral.v, 3);
    assert(bilateral.id.startsWith('rec_'));
    assert(bilateral.sig.startsWith('ed25519:'));
    assert.strictEqual(bilateral.server.name, 'github-mcp');
    assert.strictEqual(bilateral.agent_receipt.signer.name, 'agent');
    assert(bilateral.response.content_hash.startsWith('sha256:'));
  });

  it('verifyBilateral roundtrip succeeds', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    assert.strictEqual(verifyBilateral(JSON.stringify(bilateral), serverKp.publicKey), true);
  });

  it('verifyBilateral rejects replay on repeated verification by default', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    assert.strictEqual(verifyBilateral(JSON.stringify(bilateral), serverKp.publicKey), true);
    assert.throws(() => verifyBilateral(JSON.stringify(bilateral), serverKp.publicKey), /replay/i);
  });

  it('verifyBilateral with wrong server key throws (key mismatch)', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const otherKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    // WASM throws on invalid receipt / key mismatch (not boolean false).
    assert.throws(() => verifyBilateral(JSON.stringify(bilateral), otherKp.publicKey));
  });

  it('verifyBilateral rejects tampered response_hash', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    bilateral.response.content_hash = 'sha256:tampered';
    // Tampered receipt: WASM returns false (signature mismatch is the result,
    // not a structural error).
    assert.strictEqual(verifyBilateral(JSON.stringify(bilateral), serverKp.publicKey), false);
  });

  it('verifyAny dispatches v3 to bilateral verification', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    // verifyAny returns boolean from WASM (true on success).
    const ok = verifyAny(JSON.stringify(bilateral), serverKp.publicKey);
    assert.strictEqual(ok, true);
  });

  it('verifyAny returns false for v3 wrong server key', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const wrongKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    assert.strictEqual(verifyAny(JSON.stringify(bilateral), wrongKp.publicKey), false);
  });

  it('verifyAny rejects replay on repeated v3 verification by default', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    assert.strictEqual(verifyAny(JSON.stringify(bilateral), serverKp.publicKey), true);
    assert.throws(() => verifyAny(JSON.stringify(bilateral), serverKp.publicKey), /replay/i);
  });

  it('verifyBilateralWithOptions can anchor the agent identity to a trusted key', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const wrongAgentKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    assert.strictEqual(verifyBilateralWithOptions(bilateral, serverKp.publicKey, {
      trustedAgentPublicKey: agentKp.publicKey,
    }), true);
    assert.strictEqual(verifyBilateralWithOptions(bilateral, serverKp.publicKey, {
      trustedAgentPublicKey: wrongAgentKp.publicKey,
      disableReplayCheck: true,
    }), false);
  });

  it('verifyBilateralWithOptionsDetailed reports trust outcome', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    const selfConsistent: BilateralVerifyOutcome = verifyBilateralWithOptionsDetailed(
      bilateral,
      serverKp.publicKey,
      { disableReplayCheck: true },
    );
    assert.strictEqual(selfConsistent, 'agent_self_consistent');

    const trusted: BilateralVerifyOutcome = verifyBilateralWithOptionsDetailed(
      bilateral,
      serverKp.publicKey,
      {
        trustedAgentPublicKey: agentKp.publicKey,
        disableReplayCheck: true,
      },
    );
    assert.strictEqual(trusted, 'agent_trusted');
  });

  it('verifyBilateralWithOptions rejects malformed trusted agent keys', () => {
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    assert.throws(
      () => verifyBilateralWithOptions(bilateral, serverKp.publicKey, {
        trustedAgentPublicKey: 'garbage',
        disableReplayCheck: true,
      }),
      /invalid trusted agent public key/i,
    );
    assert.throws(
      () => verifyBilateralWithOptionsDetailed(bilateral, serverKp.publicKey, {
        trustedAgentPublicKey: 'garbage',
        disableReplayCheck: true,
      }),
      /invalid trusted agent public key/i,
    );
  });

  it('extensions field is unsigned: tampering does NOT invalidate signature', () => {
    // This documents the trust boundary documented on UnsignedExtensions.
    const agentKp = generateKeypair();
    const serverKp = generateKeypair();
    const agentReceipt = sign(agentKp.secretKey, action, 'agent', 'owner');
    const bilateral = signBilateral(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv',
      new Date().toISOString(),
    );
    // No extensions → still verifies.
    assert.strictEqual(verifyBilateralWithOptions(bilateral, serverKp.publicKey, {
      disableReplayCheck: true,
    }), true);
    // Add extensions after signing — signature still validates because
    // extensions are explicitly outside the signature scope.
    const tampered: BilateralReceipt = {
      ...bilateral,
      extensions: { trust_score: 100, attacker_added: 'metadata' },
    };
    assert.strictEqual(
      verifyBilateralWithOptions(tampered, serverKp.publicKey, {
        disableReplayCheck: true,
      }), true,
      'extensions added post-signing must not break verification',
    );
  });
});

// ─── verifyAny dispatch ──────────────────────────────────────────────────────

describe('verifyAny dispatch', () => {
  it('throws on unsupported version', () => {
    const fake = JSON.stringify({ v: 99, id: 'rec_fake' });
    const kp = generateKeypair();
    // Structural error: WASM throws (not boolean false).
    assert.throws(() => verifyAny(fake, kp.publicKey));
  });

  it('throws on malformed JSON', () => {
    const kp = generateKeypair();
    assert.throws(() => verifyAny('not json {', kp.publicKey));
  });

  it('throws on payload missing v field', () => {
    const fake = JSON.stringify({ id: 'rec_x' });
    const kp = generateKeypair();
    assert.throws(() => verifyAny(fake, kp.publicKey));
  });

  it('strips ed25519: prefix from public key', () => {
    const kp = generateKeypair();
    const action: SignetAction = {
      tool: 'x', params: {}, params_hash: '', target: '', transport: 'stdio',
    };
    const receipt = sign(kp.secretKey, action, 'a', 'o');
    // Both with and without prefix should verify.
    assert.strictEqual(verifyAny(JSON.stringify(receipt), kp.publicKey), true);
    const prefixed = `ed25519:${kp.publicKey}`;
    assert.strictEqual(verifyAny(JSON.stringify(receipt), prefixed), true);
  });
});

// ─── contentHash ─────────────────────────────────────────────────────────────

describe('contentHash', () => {
  it('produces sha256: prefixed hash', () => {
    const h = contentHash({ a: 1, b: 'hello' });
    assert(h.startsWith('sha256:'));
    // 64 hex chars after prefix
    assert.strictEqual(h.length, 'sha256:'.length + 64);
  });

  it('is deterministic for identical input', () => {
    const a = contentHash({ x: 1, y: 2 });
    const b = contentHash({ x: 1, y: 2 });
    assert.strictEqual(a, b);
  });

  it('is JCS-canonical: key order does not matter', () => {
    const a = contentHash({ x: 1, y: 2 });
    const b = contentHash({ y: 2, x: 1 });
    assert.strictEqual(a, b, 'JCS canonicalization sorts keys');
  });

  it('different content produces different hash', () => {
    const a = contentHash({ x: 1 });
    const b = contentHash({ x: 2 });
    assert.notStrictEqual(a, b);
  });

  it('handles primitives and arrays', () => {
    assert(contentHash('hello').startsWith('sha256:'));
    assert(contentHash(42).startsWith('sha256:'));
    assert(contentHash([1, 2, 3]).startsWith('sha256:'));
    assert(contentHash(null).startsWith('sha256:'));
  });
});

// ─── signBilateralWithOutcome ──────────────────────────────────────────────

describe('signBilateralWithOutcome', () => {
  const action: SignetAction = {
    tool: 'create_issue',
    params: { title: 'bug' },
    params_hash: '',
    target: 'mcp://github',
    transport: 'stdio',
  };

  function makeAgentReceipt() {
    const kp = generateKeypair();
    const r = sign(kp.secretKey, action, 'agent', 'owner');
    return { agentKp: kp, agentReceipt: r };
  }

  it('records executed status inside the signature scope', async () => {
    const { signBilateralWithOutcome } = await import('../src/index.js');
    const { agentReceipt } = makeAgentReceipt();
    const serverKp = generateKeypair();
    const ts = new Date().toISOString();
    const bilateral = signBilateralWithOutcome(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv', ts,
      { status: 'executed' },
    );
    assert.strictEqual(bilateral.v, 3);
    assert.deepStrictEqual(bilateral.response.outcome, { status: 'executed' });
  });

  it('records failed status with error', async () => {
    const { signBilateralWithOutcome } = await import('../src/index.js');
    const { agentReceipt } = makeAgentReceipt();
    const serverKp = generateKeypair();
    const ts = new Date().toISOString();
    const bilateral = signBilateralWithOutcome(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv', ts,
      { status: 'failed', error: 'timeout' },
    );
    assert.strictEqual(bilateral.response.outcome?.status, 'failed');
    assert.strictEqual(bilateral.response.outcome?.error, 'timeout');
  });

  it('null outcome produces a receipt with no outcome field', async () => {
    const { signBilateralWithOutcome } = await import('../src/index.js');
    const { agentReceipt } = makeAgentReceipt();
    const serverKp = generateKeypair();
    const ts = new Date().toISOString();
    const bilateral = signBilateralWithOutcome(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv', ts, null,
    );
    assert.strictEqual(bilateral.response.outcome, undefined);
  });

  it('outcome tampering invalidates the bilateral signature', async () => {
    const { signBilateralWithOutcome } = await import('../src/index.js');
    const { agentReceipt } = makeAgentReceipt();
    const serverKp = generateKeypair();
    const ts = new Date().toISOString();
    const bilateral = signBilateralWithOutcome(
      serverKp.secretKey, JSON.stringify(agentReceipt), {}, 'srv', ts,
      { status: 'failed', error: 'oops' },
    );
    // Attacker rewrites failure → success.
    bilateral.response.outcome = { status: 'executed' };
    // Verification must reject. The WASM `verifyBilateral` returns
    // `false` for signature mismatches on tampered payloads (vs throwing
    // on structural / key-mismatch errors).
    assert.strictEqual(
      verifyBilateral(JSON.stringify(bilateral), serverKp.publicKey),
      false,
    );
  });
});
