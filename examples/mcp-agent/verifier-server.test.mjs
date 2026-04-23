import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeypair, sign } from '@signet-auth/core';

import {
  inspectCurrentRequest,
  loadVerifyOptions,
  verifyReceiptPayload,
  verifySyntheticRequestPayload,
} from './verifier-server-lib.mjs';

test('loadVerifyOptions parses environment settings', () => {
  const options = loadVerifyOptions({
    SIGNET_TRUSTED_KEYS: 'ed25519:a, ed25519:b',
    SIGNET_REQUIRE_SIGNATURE: 'true',
    SIGNET_REQUIRE_TRUSTED_SIGNER: 'false',
    SIGNET_MAX_AGE: '42',
    SIGNET_EXPECTED_TARGET: 'mcp://signet-verifier',
  });

  assert.deepEqual(options, {
    trustedKeys: ['ed25519:a', 'ed25519:b'],
    requireSignature: true,
    requireTrustedSigner: false,
    maxAge: 42,
    expectedTarget: 'mcp://signet-verifier',
  });
});

test('loadVerifyOptions defaults to strict verification', () => {
  const options = loadVerifyOptions({});

  assert.deepEqual(options, {
    trustedKeys: [],
    requireSignature: true,
    requireTrustedSigner: true,
    maxAge: 300,
  });
});

test('verifyReceiptPayload validates a signed receipt', () => {
  const keypair = generateKeypair();
  const receipt = sign(
    keypair.secretKey,
    {
      tool: 'echo',
      params: { message: 'hello' },
      params_hash: '',
      target: 'mcp://signet-verifier',
      transport: 'stdio',
    },
    'demo-agent',
    'demo-owner',
  );

  const result = verifyReceiptPayload({
    receiptJson: JSON.stringify(receipt),
    publicKey: receipt.signer.pubkey,
  });

  assert.equal(result.ok, true);
  assert.equal(result.publicKeyFormat, 'prefixed');
});

test('verifySyntheticRequestPayload verifies a signed request payload', () => {
  const keypair = generateKeypair();
  const receipt = sign(
    keypair.secretKey,
    {
      tool: 'echo',
      params: { message: 'hello' },
      params_hash: '',
      target: 'mcp://signet-verifier',
      transport: 'stdio',
    },
    'demo-agent',
    'demo-owner',
  );

  const result = verifySyntheticRequestPayload(
    {
      request: {
        name: 'echo',
        arguments: { message: 'hello' },
        _meta: { _signet: receipt },
      },
      trustedKeys: [receipt.signer.pubkey],
      expectedTarget: 'mcp://signet-verifier',
    },
    loadVerifyOptions(),
  );

  assert.equal(result.verification.ok, true);
  assert.equal(result.verification.signerName, 'demo-agent');
  assert.equal(result.verification.trusted, true);
  assert.equal(result.verification.status, 'trusted');
});

test('verifySyntheticRequestPayload rejects unanchored signatures by default', () => {
  const keypair = generateKeypair();
  const receipt = sign(
    keypair.secretKey,
    {
      tool: 'echo',
      params: { message: 'hello' },
      params_hash: '',
      target: 'mcp://signet-verifier',
      transport: 'stdio',
    },
    'demo-agent',
    'demo-owner',
  );

  const result = verifySyntheticRequestPayload(
    {
      request: {
        name: 'echo',
        arguments: { message: 'hello' },
        _meta: { _signet: receipt },
      },
      expectedTarget: 'mcp://signet-verifier',
    },
    loadVerifyOptions(),
  );

  assert.equal(result.verification.ok, false);
  assert.equal(result.verification.trusted, false);
  assert.equal(result.verification.status, 'trust-not-configured');
  assert.match(result.verification.error, /trusted signer required/i);
});

test('verifySyntheticRequestPayload can opt into signature-only mode explicitly', () => {
  const keypair = generateKeypair();
  const receipt = sign(
    keypair.secretKey,
    {
      tool: 'echo',
      params: { message: 'hello' },
      params_hash: '',
      target: 'mcp://signet-verifier',
      transport: 'stdio',
    },
    'demo-agent',
    'demo-owner',
  );

  const result = verifySyntheticRequestPayload(
    {
      request: {
        name: 'echo',
        arguments: { message: 'hello' },
        _meta: { _signet: receipt },
      },
      requireTrustedSigner: false,
      expectedTarget: 'mcp://signet-verifier',
    },
    loadVerifyOptions(),
  );

  assert.equal(result.verification.ok, true);
  assert.equal(result.verification.trusted, false);
  assert.equal(result.verification.status, 'signature-only');
});

test('inspectCurrentRequest reports unsigned requests clearly', () => {
  const result = inspectCurrentRequest(
    {
      params: {
        name: 'inspect_current_request',
        arguments: { note: 'hello' },
      },
    },
    loadVerifyOptions({ SIGNET_REQUIRE_SIGNATURE: 'false' }),
    'hello',
  );

  assert.equal(result.request.hasReceipt, false);
  assert.equal(result.verification.ok, true);
  assert.equal(result.verification.status, 'unsigned-allowed');
});

test('inspectCurrentRequest rejects unsigned requests by default', () => {
  const result = inspectCurrentRequest(
    {
      params: {
        name: 'inspect_current_request',
        arguments: {},
      },
    },
    loadVerifyOptions(),
  );

  assert.equal(result.server.requireSignature, true);
  assert.equal(result.server.requireTrustedSigner, true);
  assert.equal(result.request.hasReceipt, false);
  assert.equal(result.verification.ok, false);
  assert.equal(result.verification.status, 'unsigned-rejected');
});
