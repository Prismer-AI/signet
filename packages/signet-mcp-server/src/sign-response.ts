import {
  contentHash,
  signBilateralWithOutcome,
  verify,
  type BilateralReceipt,
  type SignetOutcome,
  type SignetReceipt,
} from '@signet-auth/core';
import { getVerifiedRequestContext } from './verify-request.js';

export interface SignResponseOptions {
  serverKey: string;    // raw base64 secret key (64-byte keypair)
  serverName: string;
  /** Explicit opt-in for signature-only deployments without trust anchors. */
  allowUntrustedRequest?: boolean;
  /** Override the default inferred outcome. */
  outcome?: SignetOutcome;
}

function inferOutcome(response: unknown): SignetOutcome {
  if (response && typeof response === 'object' && 'isError' in response && (response as { isError?: unknown }).isError === true) {
    const content = (response as { content?: unknown }).content;
    const text = Array.isArray(content)
      ? content
          .find((item): item is { text?: unknown } => typeof item === 'object' && item !== null)
          ?.text
      : undefined;
    return {
      status: 'failed',
      error: typeof text === 'string' ? text : 'MCP tool result returned isError=true',
    };
  }
  return { status: 'executed' };
}

export function signResponse(
  request: { params?: Record<string, unknown> },
  response: unknown,
  options: SignResponseOptions,
): BilateralReceipt {
  // 1. Extract agent receipt from request._meta._signet
  const signet = (request.params as any)?._meta?._signet;
  if (!signet) throw new Error('request has no _meta._signet — call verifyRequest() first');

  // 2. Validate receipt shape before embedding
  if (!signet || typeof signet !== 'object' || !signet.sig || !signet.signer || !signet.action) {
    throw new Error('_meta._signet is not a valid SignetReceipt — call verifyRequest() first');
  }

  // 3. Require a prior in-process verification step so co-signing cannot be
  // triggered by a self-consistent but otherwise untrusted receipt.
  const verification = getVerifiedRequestContext(request);
  if (!verification) {
    throw new Error('request has no verification context — call verifyRequest() and require verified.ok before signResponse()');
  }
  if (!options.allowUntrustedRequest && !verification.trusted) {
    throw new Error('request receipt was verified without trust anchors — refusing to co-sign untrusted signer');
  }

  const receipt = signet as SignetReceipt;
  if (verification.receiptId !== receipt.id || verification.signerPubkey !== receipt.signer.pubkey) {
    throw new Error('request receipt changed after verification — refusing to co-sign');
  }
  const requestTool = (request.params as Record<string, unknown> | undefined)?.name;
  if (requestTool !== undefined && requestTool !== verification.tool) {
    throw new Error('request tool changed after verification — refusing to co-sign');
  }
  const requestArgsHash = contentHash((request.params as Record<string, unknown> | undefined)?.arguments ?? null);
  if (requestArgsHash !== verification.argsHash) {
    throw new Error('request arguments changed after verification — refusing to co-sign');
  }

  // 4. Verify the agent signature before co-signing
  const barePubkey = receipt.signer.pubkey.startsWith('ed25519:')
    ? receipt.signer.pubkey.slice('ed25519:'.length)
    : receipt.signer.pubkey;
  if (!verify(receipt, barePubkey)) {
    throw new Error('agent receipt signature is invalid — refusing to co-sign');
  }

  // 5. Sign bilateral: server key + agent receipt JSON + response content + server name + timestamp
  const tsResponse = new Date().toISOString();
  return signBilateralWithOutcome(
    options.serverKey,
    JSON.stringify(signet),
    response,
    options.serverName,
    tsResponse,
    options.outcome ?? inferOutcome(response),
  );
}
