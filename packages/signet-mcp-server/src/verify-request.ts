import { verify, contentHash, type SignetReceipt } from '@signet-auth/core';
import type { NonceCache } from './nonce-cache.js';

export interface VerifyOptions {
  /** List of trusted "ed25519:<base64>" pubkeys.
   *  If empty, trust any signer with a valid signature (skip trust check). */
  trustedKeys?: string[];
  /** Reject unsigned requests. Default: true. */
  requireSignature?: boolean;
  /** Max age of receipt in seconds. Default: 300 (5 min). */
  maxAge?: number;
  /** If set, receipt.action.target must match this value. */
  expectedTarget?: string;
  /** If set, rejects duplicate nonces (replay protection). */
  nonceCache?: NonceCache;
  /** Clock skew tolerance in seconds for future-dated receipts. Default: 30. */
  clockSkewTolerance?: number;
}

export interface VerifyResult {
  ok: boolean;
  signerName?: string;
  signerPubkey?: string;
  error?: string;
  hasReceipt: boolean;
  trusted: boolean;
}

export interface VerifiedRequestContext {
  receiptId: string;
  signerName: string;
  signerPubkey: string;
  trusted: boolean;
  tool: string;
  argsHash: string;
}

const DEFAULT_CLOCK_SKEW_TOLERANCE_S = 30;
const VERIFIED_REQUEST_CONTEXT = Symbol('signetVerifiedRequestContext');

type RequestWithVerifiedContext = {
  params?: Record<string, unknown>;
} & Record<symbol, unknown>;

function clearVerifiedRequestContext(request: { params?: Record<string, unknown> }): void {
  Reflect.deleteProperty(request as RequestWithVerifiedContext, VERIFIED_REQUEST_CONTEXT);
}

function setVerifiedRequestContext(
  request: { params?: Record<string, unknown> },
  context: VerifiedRequestContext,
): void {
  Object.defineProperty(request as RequestWithVerifiedContext, VERIFIED_REQUEST_CONTEXT, {
    value: context,
    configurable: true,
  });
}

export function getVerifiedRequestContext(
  request: { params?: Record<string, unknown> },
): VerifiedRequestContext | undefined {
  return (request as RequestWithVerifiedContext)[VERIFIED_REQUEST_CONTEXT] as
    | VerifiedRequestContext
    | undefined;
}

export function verifyRequest(
  request: { params?: Record<string, unknown> },
  options: VerifyOptions,
): VerifyResult {
  clearVerifiedRequestContext(request);

  const requireSig = options.requireSignature ?? true;
  const maxAgeMs = (options.maxAge ?? 300) * 1000;
  const clockSkewMs = (options.clockSkewTolerance ?? DEFAULT_CLOCK_SKEW_TOLERANCE_S) * 1000;

  // 1. Extract _meta._signet
  const meta = (request.params as Record<string, unknown> | undefined)?._meta;
  const signet = (meta as Record<string, unknown> | undefined)?._signet;

  // 2. Check presence
  if (!signet) {
    if (requireSig) {
      return { ok: false, error: 'unsigned request', hasReceipt: false, trusted: false };
    }
    return { ok: true, hasReceipt: false, trusted: false };
  }

  // 3. Validate receipt shape
  const s = signet as Record<string, unknown>;
  if (!s['v'] || !s['sig'] || !s['action'] || !s['signer'] || !s['ts']) {
    return { ok: false, error: 'malformed receipt', hasReceipt: true, trusted: false };
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
      return { ok: false, error: 'invalid signature', hasReceipt: true, trusted: false };
    }
  } catch {
    return { ok: false, error: 'invalid signature', hasReceipt: true, trusted: false };
  }

  // 4b. Nonce dedup (replay protection)
  if (options.nonceCache && receipt.nonce) {
    if (!options.nonceCache.check(receipt.signer.pubkey, receipt.nonce)) {
      return { ok: false, error: 'duplicate nonce: possible replay', hasReceipt: true, trusted: false };
    }
  }

  // 5. Check trusted keys (using prefixed format to match receipt.signer.pubkey)
  // Empty trustedKeys = "verify signature only, don't check trust". Non-empty = "must be in list".
  const trustedKeys = options.trustedKeys ?? [];
  if (trustedKeys.length > 0 && !trustedKeys.includes(prefixedPubkey)) {
    return { ok: false, error: `untrusted signer: ${prefixedPubkey}`, hasReceipt: true, trusted: false };
  }

  // 6. Check freshness (ts is guaranteed by shape check above)
  const receiptTime = new Date(receipt.ts).getTime();
  const now = Date.now();
  if (isNaN(receiptTime)) {
    return { ok: false, error: 'invalid receipt timestamp', hasReceipt: true, trusted: false };
  }
  if (receiptTime < now - maxAgeMs) {
    return { ok: false, error: 'receipt too old', hasReceipt: true, trusted: false };
  }
  if (receiptTime > now + clockSkewMs) {
    return { ok: false, error: 'receipt from future', hasReceipt: true, trusted: false };
  }

  // 7. Check target
  if (options.expectedTarget && receipt.action.target !== options.expectedTarget) {
    return {
      ok: false,
      error: `target mismatch: expected ${options.expectedTarget}, got ${receipt.action.target}`,
      hasReceipt: true,
      trusted: false,
    };
  }

  // 8. Anti-staple: receipt.action.tool must match request.params.name
  const requestTool = (request.params as Record<string, unknown> | undefined)?.['name'];
  if (requestTool !== undefined && receipt.action.tool !== requestTool) {
    return {
      ok: false,
      error: `tool mismatch: receipt signed for "${receipt.action.tool}", request is for "${requestTool}"`,
      hasReceipt: true,
      trusted: false,
    };
  }

  // 9. Anti-staple: receipt.action.params must match request.params.arguments
  const requestArgs = (request.params as Record<string, unknown> | undefined)?.['arguments'];
  const signedHash = contentHash(receipt.action.params ?? null);
  const actualHash = contentHash(requestArgs ?? null);
  if (signedHash !== actualHash) {
    return {
      ok: false,
      error: 'params mismatch: signed params differ from request arguments',
      hasReceipt: true,
      trusted: false,
    };
  }

  const trusted = trustedKeys.length > 0;
  setVerifiedRequestContext(request, {
    receiptId: receipt.id,
    signerName: receipt.signer.name,
    signerPubkey: receipt.signer.pubkey,
    trusted,
    tool: typeof requestTool === 'string' ? requestTool : receipt.action.tool,
    argsHash: actualHash,
  });

  // All checks pass
  return {
    ok: true,
    signerName: receipt.signer.name,
    signerPubkey: receipt.signer.pubkey,
    hasReceipt: true,
    trusted,
  };
}
