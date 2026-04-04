import { signBilateral, verify, type BilateralReceipt, type SignetReceipt } from '@signet-auth/core';

export interface SignResponseOptions {
  serverKey: string;    // raw base64 secret key (64-byte keypair)
  serverName: string;
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

  // 3. Verify the agent signature before co-signing
  const receipt = signet as SignetReceipt;
  const barePubkey = receipt.signer.pubkey.replace('ed25519:', '');
  if (!verify(receipt, barePubkey)) {
    throw new Error('agent receipt signature is invalid — refusing to co-sign');
  }

  // 4. Sign bilateral: server key + agent receipt JSON + response content + server name + timestamp
  const tsResponse = new Date().toISOString();
  return signBilateral(
    options.serverKey,
    JSON.stringify(signet),
    response,
    options.serverName,
    tsResponse,
  );
}
