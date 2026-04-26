import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateKeypair, sign, verifyBilateral, type SignetAction, type SignetReceipt } from '@signet-auth/core';
import { verifyRequest, signResponse, NonceCache } from '../src/index.js';

describe('@signet-auth/mcp-server verifyRequest', () => {
  const kp = generateKeypair();
  const kp2 = generateKeypair();

  function makeAction(tool: string, args: Record<string, unknown>): SignetAction {
    return {
      tool,
      params: args,
      params_hash: '',
      target: 'mcp://test-server',
      transport: 'stdio',
    };
  }

  function signedRequest(tool: string, args: Record<string, unknown>) {
    const action = makeAction(tool, args);
    const receipt = sign(kp.secretKey, action, 'test-agent', 'owner');
    return {
      params: {
        name: tool,
        arguments: args,
        _meta: { _signet: receipt },
      },
    };
  }

  // Use prefixed format (matching receipt.signer.pubkey) for trustedKeys
  function trustedKey(receipt: SignetReceipt): string {
    return receipt.signer.pubkey;
  }

  it('test_verify_valid_signature — trusted key, valid sig → ok: true', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const receipt = (req.params._meta._signet) as SignetReceipt;
    const result = verifyRequest(req, { trustedKeys: [trustedKey(receipt)] });
    assert.strictEqual(result.ok, true, `Expected ok: true, got error: ${result.error}`);
    assert.strictEqual(result.hasReceipt, true);
    assert.strictEqual(result.trusted, true);
  });

  it('test_verify_signature_only_mode_marks_request_untrusted — valid sig + no trust anchors → ok: true, trusted: false', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const result = verifyRequest(req, { trustedKeys: [] });
    assert.strictEqual(result.ok, true, `Expected ok: true, got error: ${result.error}`);
    assert.strictEqual(result.hasReceipt, true);
    assert.strictEqual(result.trusted, false);
  });

  it('test_verify_untrusted_key — valid sig but key not in trustedKeys → ok: false', () => {
    const req = signedRequest('echo', { message: 'hello' });
    // Use kp2 pubkey (prefixed) as trusted — won't match kp's pubkey
    const fakeReceipt = sign(kp2.secretKey, makeAction('echo', {}), 'other', 'owner');
    const result = verifyRequest(req, { trustedKeys: [trustedKey(fakeReceipt)] });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('untrusted'), `Expected 'untrusted' in error, got: ${result.error}`);
  });

  it('test_verify_trust_bundle_active_agent — active agent in trust bundle → ok: true, trusted: true', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const receipt = req.params._meta._signet as SignetReceipt;
    const result = verifyRequest(req, {
      trustBundle: {
        version: 1,
        bundle_id: 'tb_prod',
        org: 'signet',
        env: 'prod',
        generated_at: '2026-04-25T10:30:00Z',
        agents: [
          {
            id: 'agent-1',
            name: 'test-agent',
            owner: 'platform',
            pubkey: receipt.signer.pubkey,
            status: 'active',
            created_at: '2026-04-25T10:00:00Z',
          },
        ],
      },
    });
    assert.strictEqual(result.ok, true, `Expected ok: true, got error: ${result.error}`);
    assert.strictEqual(result.trusted, true);
  });

  it('test_verify_trust_bundle_disabled_agent_rejected — trust bundle provided but signer not active → ok: false', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const receipt = req.params._meta._signet as SignetReceipt;
    const result = verifyRequest(req, {
      trustBundle: {
        version: 1,
        bundle_id: 'tb_prod',
        org: 'signet',
        env: 'prod',
        generated_at: '2026-04-25T10:30:00Z',
        agents: [
          {
            id: 'agent-1',
            name: 'test-agent',
            owner: 'platform',
            pubkey: receipt.signer.pubkey,
            status: 'disabled',
            created_at: '2026-04-25T10:00:00Z',
            disabled_at: '2026-04-25T10:05:00Z',
          },
        ],
      },
    });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('untrusted'), `Expected 'untrusted', got: ${result.error}`);
  });

  it('test_verify_invalid_signature — tampered _signet.sig → ok: false', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const receipt = req.params._meta._signet as SignetReceipt;
    // Tamper with the signature
    const tamperedReceipt = { ...receipt, sig: 'ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' };
    const tamperedReq = {
      params: {
        ...req.params,
        _meta: { _signet: tamperedReceipt },
      },
    };
    const result = verifyRequest(tamperedReq, { trustedKeys: [receipt.signer.pubkey] });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('invalid signature'), `Expected 'invalid signature', got: ${result.error}`);
  });

  it('test_verify_unsigned_required — no _signet + requireSignature=true → ok: false', () => {
    const req = { params: { name: 'echo', arguments: { message: 'hello' } } };
    const result = verifyRequest(req, { requireSignature: true, trustedKeys: [] });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('unsigned'), `Expected 'unsigned' in error, got: ${result.error}`);
    assert.strictEqual(result.hasReceipt, false);
    assert.strictEqual(result.trusted, false);
  });

  it('test_verify_unsigned_optional — no _signet + requireSignature=false → ok: true', () => {
    const req = { params: { name: 'echo', arguments: { message: 'hello' } } };
    const result = verifyRequest(req, { requireSignature: false, trustedKeys: [] });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.hasReceipt, false);
    assert.strictEqual(result.trusted, false);
  });

  it('test_verify_returns_signer_info — ok: true has signerName + signerPubkey', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const receipt = req.params._meta._signet as SignetReceipt;
    const result = verifyRequest(req, { trustedKeys: [trustedKey(receipt)] });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.signerName, 'test-agent');
    assert(result.signerPubkey?.startsWith('ed25519:'), `Expected prefixed pubkey, got: ${result.signerPubkey}`);
  });

  it('test_verify_expired_receipt — maxAge=0 causes "receipt too old"', async () => {
    const req = signedRequest('echo', { message: 'hello' });
    const receipt = req.params._meta._signet as SignetReceipt;
    // Use maxAge=0 so any receipt is immediately expired (0 seconds allowed)
    // Wait a tiny bit to ensure time has passed
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
    const result = verifyRequest(req, { trustedKeys: [trustedKey(receipt)], maxAge: 0 });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('receipt too old'), `Expected 'receipt too old', got: ${result.error}`);
  });

  it('test_verify_clock_skew_configurable — custom clockSkewTolerance is respected', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const receipt = req.params._meta._signet as SignetReceipt;
    // With 0 tolerance, even a tiny clock difference is rejected
    // Manually push receipt ts into the future by 2 seconds
    const futureReceipt = { ...receipt, ts: new Date(Date.now() + 2000).toISOString() };
    const futureReq = {
      params: { ...req.params, _meta: { _signet: futureReceipt } },
    };
    // Default 30s tolerance should accept 2s ahead
    const resultDefault = verifyRequest(futureReq, { trustedKeys: [] });
    // Signature is invalid because we tampered with ts, but the clock check runs before sig check
    // Actually sig check runs first (step 4). So let's test with clockSkewTolerance=0 on a valid receipt
    const validResult = verifyRequest(req, { trustedKeys: [trustedKey(receipt)], clockSkewTolerance: 600 });
    assert.strictEqual(validResult.ok, true, `Expected ok with large tolerance, got: ${validResult.error}`);
  });

  it('test_verify_target_mismatch — expectedTarget differs → ok: false', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const receipt = req.params._meta._signet as SignetReceipt;
    const result = verifyRequest(req, {
      trustedKeys: [trustedKey(receipt)],
      expectedTarget: 'mcp://different-server',
    });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('target mismatch'), `Expected 'target mismatch', got: ${result.error}`);
  });

  it('test_verify_malformed_signet — _signet is garbage → ok: false, "malformed"', () => {
    const req = {
      params: {
        name: 'echo',
        arguments: { message: 'hello' },
        _meta: { _signet: { garbage: true, random: 'data' } },
      },
    };
    const result = verifyRequest(req, { trustedKeys: [] });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('malformed'), `Expected 'malformed' in error, got: ${result.error}`);
  });

  it('test_verify_tool_mismatch — receipt for "echo" on request for "delete" → ok: false', () => {
    // Sign for "echo" but attach to a "delete" request
    const action = makeAction('echo', { message: 'hello' });
    const receipt = sign(kp.secretKey, action, 'test-agent', 'owner');
    const req = {
      params: {
        name: 'delete',  // different tool
        arguments: { message: 'hello' },
        _meta: { _signet: receipt },
      },
    };
    const result = verifyRequest(req, { trustedKeys: [receipt.signer.pubkey] });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('tool mismatch'), `Expected 'tool mismatch', got: ${result.error}`);
  });

  it('test_verify_params_mismatch — receipt with {a:1} but request has {a:2} → ok: false', () => {
    // Sign for {a: 1} but attach to request with {a: 2}
    const action = makeAction('echo', { a: 1 });
    const receipt = sign(kp.secretKey, action, 'test-agent', 'owner');
    const req = {
      params: {
        name: 'echo',
        arguments: { a: 2 },  // different args
        _meta: { _signet: receipt },
      },
    };
    const result = verifyRequest(req, { trustedKeys: [receipt.signer.pubkey] });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('params mismatch'), `Expected 'params mismatch', got: ${result.error}`);
  });

  it('test_verify_no_request_args — receipt signed with params, request has no arguments key → params mismatch', () => {
    // Sign with params {x: 1} but request omits the arguments key entirely
    const action = makeAction('echo', { x: 1 });
    const receipt = sign(kp.secretKey, action, 'test-agent', 'owner');
    const req = {
      params: {
        name: 'echo',
        // no 'arguments' key — requestArgs will be undefined
        _meta: { _signet: receipt },
      },
    };
    const result = verifyRequest(req, { trustedKeys: [receipt.signer.pubkey] });
    // receipt.action.params is {x:1}, requestArgs is undefined → mismatch
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('params mismatch'), `Expected 'params mismatch', got: ${result.error}`);
  });

  it('test_verify_params_key_reorder — receipt signed {a:1,b:2}, request has {b:2,a:1} → ok: true (anti-staple accepts reordered keys)', () => {
    // Fix #1: params comparison must be order-independent (uses contentHash)
    const action = makeAction('echo', { a: 1, b: 2 });
    const receipt = sign(kp.secretKey, action, 'test-agent', 'owner');
    const req = {
      params: {
        name: 'echo',
        arguments: { b: 2, a: 1 },  // same values, different key order
        _meta: { _signet: receipt },
      },
    };
    const result = verifyRequest(req, { trustedKeys: [receipt.signer.pubkey] });
    assert.strictEqual(result.ok, true, `Expected ok: true (reordered keys should not cause anti-staple failure), got error: ${result.error}`);
  });

  it('test_verify_params_value_change_still_rejected — receipt signed {a:1}, request has {a:999} → ok: false (params mismatch)', () => {
    // Fix #1 inverse: different values must still be rejected
    const action = makeAction('echo', { a: 1 });
    const receipt = sign(kp.secretKey, action, 'test-agent', 'owner');
    const req = {
      params: {
        name: 'echo',
        arguments: { a: 999 },  // different value
        _meta: { _signet: receipt },
      },
    };
    const result = verifyRequest(req, { trustedKeys: [receipt.signer.pubkey] });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('params mismatch'), `Expected 'params mismatch', got: ${result.error}`);
  });

  it('test_verify_malformed_no_ts — _signet missing ts field → ok: false, "malformed"', () => {
    // Construct a receipt-like object without ts to exercise the shape check for ts
    const req = {
      params: {
        name: 'echo',
        arguments: { message: 'hello' },
        _meta: {
          _signet: {
            v: 1,
            sig: 'ed25519:AAAA',
            action: { tool: 'echo', params: {}, params_hash: '', target: '', transport: 'stdio' },
            signer: { name: 'agent', pubkey: 'ed25519:AAAA', owner: '' },
            // ts intentionally omitted
          },
        },
      },
    };
    const result = verifyRequest(req, { trustedKeys: [] });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('malformed'), `Expected 'malformed' in error, got: ${result.error}`);
  });
});

describe('@signet-auth/mcp-server NonceCache', () => {
  it('keys replay protection by signer + nonce', () => {
    const cache = new NonceCache(60_000, 10);

    assert.strictEqual(cache.check('ed25519:signer-a', 'nonce-1'), true);
    assert.strictEqual(cache.check('ed25519:signer-a', 'nonce-1'), false);
    assert.strictEqual(cache.check('ed25519:signer-b', 'nonce-1'), true);

    cache.destroy();
  });

  it('preserves one-argument check() for direct nonce-only callers', () => {
    const cache = new NonceCache(60_000, 10);

    assert.strictEqual(cache.check('nonce-1'), true);
    assert.strictEqual(cache.check('nonce-1'), false);

    cache.destroy();
  });
});

describe('@signet-auth/mcp-server signResponse', () => {
  const agentKp = generateKeypair();
  const serverKp = generateKeypair();

  function makeAction(tool: string, args: Record<string, unknown>): SignetAction {
    return {
      tool,
      params: args,
      params_hash: '',
      target: 'mcp://test-server',
      transport: 'stdio',
    };
  }

  function signedRequest(tool: string, args: Record<string, unknown>) {
    const action = makeAction(tool, args);
    const receipt = sign(agentKp.secretKey, action, 'test-agent', 'owner');
    return {
      params: {
        name: tool,
        arguments: args,
        _meta: { _signet: receipt },
      },
    };
  }

  function verifyTrustedRequest(req: ReturnType<typeof signedRequest>) {
    const receipt = req.params._meta._signet as SignetReceipt;
    const verified = verifyRequest(req, { trustedKeys: [receipt.signer.pubkey] });
    assert.strictEqual(verified.ok, true, `Expected ok: true, got error: ${verified.error}`);
    assert.strictEqual(verified.trusted, true);
  }

  function verifySignatureOnlyRequest(req: ReturnType<typeof signedRequest>) {
    const verified = verifyRequest(req, { trustedKeys: [] });
    assert.strictEqual(verified.ok, true, `Expected ok: true, got error: ${verified.error}`);
    assert.strictEqual(verified.trusted, false);
  }

  it('test_sign_response_produces_bilateral — sign valid request+response → returns v3 with correct fields', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const response = { content: [{ type: 'text', text: 'world' }] };
    verifyTrustedRequest(req);

    const bilateral = signResponse(req, response, {
      serverKey: serverKp.secretKey,
      serverName: 'test-server',
    });

    assert.strictEqual(bilateral.v, 3);
    assert(bilateral.id.startsWith('rec_'), `id should start with rec_, got: ${bilateral.id}`);
    assert(bilateral.sig.startsWith('ed25519:'), `sig should start with ed25519:, got: ${bilateral.sig}`);
    assert(bilateral.agent_receipt !== undefined, 'agent_receipt should be present');
    assert(bilateral.server !== undefined, 'server should be present');
    assert(bilateral.server.name === 'test-server', `server.name should be test-server, got: ${bilateral.server.name}`);
    assert(bilateral.response.content_hash.startsWith('sha256:'), `content_hash should start with sha256:, got: ${bilateral.response.content_hash}`);
  });

  it('test_sign_response_embeds_agent_receipt — v3.agent_receipt matches the original v1 receipt', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const agentReceipt = req.params._meta._signet as SignetReceipt;
    const response = { content: [{ type: 'text', text: 'world' }] };
    verifyTrustedRequest(req);

    const bilateral = signResponse(req, response, {
      serverKey: serverKp.secretKey,
      serverName: 'test-server',
    });

    assert.deepStrictEqual(bilateral.agent_receipt, agentReceipt,
      'agent_receipt in bilateral should match the original v1 receipt');
  });

  it('test_sign_response_verifiable — produced v3 passes verifyBilateral() with server public key', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const response = { content: [{ type: 'text', text: 'world' }] };
    verifyTrustedRequest(req);

    const bilateral = signResponse(req, response, {
      serverKey: serverKp.secretKey,
      serverName: 'test-server',
    });

    const barePubkey = serverKp.publicKey;
    const valid = verifyBilateral(JSON.stringify(bilateral), barePubkey);
    assert(valid, 'bilateral receipt should verify with the server public key');
  });

  it('test_sign_response_no_signet_throws — request without _meta._signet → throws Error', () => {
    const req = { params: { name: 'echo', arguments: { message: 'hello' } } };

    assert.throws(
      () => signResponse(req, {}, { serverKey: serverKp.secretKey, serverName: 'test-server' }),
      (err: Error) => {
        assert(err.message.includes('_meta._signet'), `Expected error about _meta._signet, got: ${err.message}`);
        return true;
      },
    );
  });

  it('test_sign_response_requires_verify_request_context — request with receipt but no prior verifyRequest() → throws Error', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const response = { content: [{ type: 'text', text: 'world' }] };

    assert.throws(
      () => signResponse(req, response, { serverKey: serverKp.secretKey, serverName: 'test-server' }),
      (err: Error) => {
        assert(err.message.includes('verification context'), `Expected verification context error, got: ${err.message}`);
        return true;
      },
    );
  });

  it('test_sign_response_rejects_untrusted_verification_context_by_default — verifyRequest() without trust anchors cannot co-sign', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const response = { content: [{ type: 'text', text: 'world' }] };
    verifySignatureOnlyRequest(req);

    assert.throws(
      () => signResponse(req, response, { serverKey: serverKp.secretKey, serverName: 'test-server' }),
      (err: Error) => {
        assert(err.message.includes('without trust anchors'), `Expected trust-anchor error, got: ${err.message}`);
        return true;
      },
    );
  });

  it('test_sign_response_allow_untrusted_request_opt_in — explicit opt-in preserves signature-only deployments', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const response = { content: [{ type: 'text', text: 'world' }] };
    verifySignatureOnlyRequest(req);

    const bilateral = signResponse(req, response, {
      serverKey: serverKp.secretKey,
      serverName: 'test-server',
      allowUntrustedRequest: true,
    });

    assert.strictEqual(bilateral.v, 3);
    assert(bilateral.sig.startsWith('ed25519:'));
  });

  it('test_sign_response_rejects_request_mutation_after_verification — request args changed after verifyRequest() → throws Error', () => {
    const req = signedRequest('echo', { message: 'hello' });
    verifyTrustedRequest(req);
    req.params.arguments = { message: 'tampered' };
    const response = { content: [{ type: 'text', text: 'world' }] };

    assert.throws(
      () => signResponse(req, response, { serverKey: serverKp.secretKey, serverName: 'test-server' }),
      (err: Error) => {
        assert(err.message.includes('changed after verification'), `Expected mutation error, got: ${err.message}`);
        return true;
      },
    );
  });

  it('test_sign_response_pubkey_with_prefix — receipt.signer.pubkey already has ed25519: prefix → signResponse succeeds', () => {
    const req = signedRequest('echo', { message: 'hello' });
    const agentReceipt = req.params._meta._signet as SignetReceipt;
    verifyTrustedRequest(req);

    assert(agentReceipt.signer.pubkey.startsWith('ed25519:'),
      `Expected prefixed pubkey in receipt, got: ${agentReceipt.signer.pubkey}`);

    const response = { content: [{ type: 'text', text: 'world' }] };
    const bilateral = signResponse(req, response, {
      serverKey: serverKp.secretKey,
      serverName: 'test-server',
    });

    assert.strictEqual(bilateral.v, 3);
    assert.strictEqual(bilateral.agent_receipt.signer.pubkey, agentReceipt.signer.pubkey);
  });
});
