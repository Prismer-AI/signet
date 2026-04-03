import { verify, type SignetReceipt } from '@signet-auth/core';

export interface VerifyOptions {
  /** List of trusted "ed25519:<base64>" pubkeys.
   *  If omitted and requireSignature=true, ALL signed requests are rejected. */
  trustedKeys?: string[];
  /** Reject unsigned requests. Default: true. */
  requireSignature?: boolean;
  /** Max age of receipt in seconds. Default: 300 (5 min). */
  maxAge?: number;
  /** If set, receipt.action.target must match this value. */
  expectedTarget?: string;
}

export interface VerifyResult {
  ok: boolean;
  signerName?: string;
  signerPubkey?: string;
  error?: string;
}

const CLOCK_SKEW_TOLERANCE_MS = 30_000; // 30 seconds

export function verifyRequest(
  request: { params?: Record<string, unknown> },
  options: VerifyOptions,
): VerifyResult {
  const requireSig = options.requireSignature ?? true;
  const maxAgeMs = (options.maxAge ?? 300) * 1000;

  // 1. Extract _meta._signet
  const meta = (request.params as Record<string, unknown> | undefined)?._meta;
  const signet = (meta as Record<string, unknown> | undefined)?._signet;

  // 2. Check presence
  if (!signet) {
    if (requireSig) {
      return { ok: false, error: 'unsigned request' };
    }
    return { ok: true };
  }

  // 3. Validate receipt shape
  const s = signet as Record<string, unknown>;
  if (!s['v'] || !s['sig'] || !s['action'] || !s['signer']) {
    return { ok: false, error: 'malformed receipt' };
  }

  const receipt = signet as SignetReceipt;

  // 4. Verify signature
  // receipt.signer.pubkey has "ed25519:" prefix; verify() takes bare base64
  const prefixedPubkey = receipt.signer.pubkey;
  const barePubkey = prefixedPubkey.startsWith('ed25519:')
    ? prefixedPubkey.slice('ed25519:'.length)
    : prefixedPubkey;

  try {
    const valid = verify(receipt, barePubkey);
    if (!valid) {
      return { ok: false, error: 'invalid signature' };
    }
  } catch {
    return { ok: false, error: 'invalid signature' };
  }

  // 5. Check trusted keys (using prefixed format to match receipt.signer.pubkey)
  const trustedKeys = options.trustedKeys ?? [];
  if (!trustedKeys.includes(prefixedPubkey)) {
    return { ok: false, error: `untrusted signer: ${prefixedPubkey}` };
  }

  // 6. Check freshness
  if (receipt.ts) {
    const receiptTime = new Date(receipt.ts).getTime();
    const now = Date.now();
    if (isNaN(receiptTime)) {
      return { ok: false, error: 'invalid receipt timestamp' };
    }
    if (receiptTime < now - maxAgeMs) {
      return { ok: false, error: 'receipt too old' };
    }
    if (receiptTime > now + CLOCK_SKEW_TOLERANCE_MS) {
      return { ok: false, error: 'receipt from future' };
    }
  }

  // 7. Check target
  if (options.expectedTarget && receipt.action.target !== options.expectedTarget) {
    return {
      ok: false,
      error: `target mismatch: expected ${options.expectedTarget}, got ${receipt.action.target}`,
    };
  }

  // 8. Anti-staple: receipt.action.tool must match request.params.name
  const requestTool = (request.params as Record<string, unknown> | undefined)?.['name'];
  if (requestTool !== undefined && receipt.action.tool !== requestTool) {
    return {
      ok: false,
      error: `tool mismatch: receipt signed for "${receipt.action.tool}", request is for "${requestTool}"`,
    };
  }

  // 9. Anti-staple: receipt.action.params must match request.params.arguments
  const requestArgs = (request.params as Record<string, unknown> | undefined)?.['arguments'];
  if (requestArgs !== undefined && receipt.action.params !== undefined) {
    const signedParams = JSON.stringify(receipt.action.params);
    const actualParams = JSON.stringify(requestArgs);
    if (signedParams !== actualParams) {
      return { ok: false, error: 'params mismatch: signed params differ from request arguments' };
    }
  }

  // All checks pass
  return {
    ok: true,
    signerName: receipt.signer.name,
    signerPubkey: receipt.signer.pubkey,
  };
}
