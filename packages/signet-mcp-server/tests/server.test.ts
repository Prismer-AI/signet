import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateKeypair, sign, type SignetAction, type SignetReceipt } from '@signet-auth/core';
import { verifyRequest } from '../src/index.js';

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
  });

  it('test_verify_untrusted_key — valid sig but key not in trustedKeys → ok: false', () => {
    const req = signedRequest('echo', { message: 'hello' });
    // Use kp2 pubkey (prefixed) as trusted — won't match kp's pubkey
    const fakeReceipt = sign(kp2.secretKey, makeAction('echo', {}), 'other', 'owner');
    const result = verifyRequest(req, { trustedKeys: [trustedKey(fakeReceipt)] });
    assert.strictEqual(result.ok, false);
    assert(result.error?.includes('untrusted'), `Expected 'untrusted' in error, got: ${result.error}`);
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
  });

  it('test_verify_unsigned_optional — no _signet + requireSignature=false → ok: true', () => {
    const req = { params: { name: 'echo', arguments: { message: 'hello' } } };
    const result = verifyRequest(req, { requireSignature: false, trustedKeys: [] });
    assert.strictEqual(result.ok, true);
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
