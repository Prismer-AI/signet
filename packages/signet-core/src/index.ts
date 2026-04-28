// @signet-auth/core — TypeScript wrapper for signet WASM
import { wasm_generate_keypair, wasm_sign, wasm_verify, wasm_sign_compound, wasm_verify_any, wasm_sign_bilateral, wasm_sign_bilateral_with_outcome, wasm_verify_bilateral, wasm_content_hash, wasm_sign_delegation, wasm_verify_delegation, wasm_sign_authorized, wasm_verify_authorized, wasm_parse_policy_yaml, wasm_evaluate_policy, wasm_sign_with_policy, wasm_compute_policy_hash, wasm_sign_with_expiration, wasm_verify_allow_expired, wasm_verify_bilateral_with_options } from '../wasm/signet_wasm.js';

export interface SignetKeypair {
  secretKey: string;
  publicKey: string;
}

export interface SignetAction {
  tool: string;
  params: unknown;
  params_hash: string;
  target: string;
  transport: string;
  session?: string;
  call_id?: string;
  response_hash?: string;
  trace_id?: string;
  parent_receipt_id?: string;
}

export interface SignetSigner {
  pubkey: string;
  name: string;
  owner: string;
}

export interface SignetReceipt {
  v: number;
  id: string;
  action: SignetAction;
  signer: SignetSigner;
  ts: string;
  exp?: string;
  nonce: string;
  sig: string;
}

function normalizePublicKey(publicKey: string): string {
  return publicKey.startsWith('ed25519:') ? publicKey.slice('ed25519:'.length) : publicKey;
}

function parseAndNormalizePublicKey(publicKey: string, label: string): string {
  const bare = normalizePublicKey(publicKey);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(bare) || bare.length % 4 !== 0) {
    throw new Error(`invalid ${label}: invalid base64 public key`);
  }
  const decoded = Buffer.from(bare, 'base64');
  if (decoded.toString('base64').replace(/=+$/u, '') !== bare.replace(/=+$/u, '')) {
    throw new Error(`invalid ${label}: invalid base64 public key`);
  }
  if (decoded.length !== 32) {
    throw new Error(`invalid ${label}: public key must be 32 bytes`);
  }
  return bare;
}

export function generateKeypair(): SignetKeypair {
  const json = wasm_generate_keypair();
  const result = JSON.parse(json);
  return {
    secretKey: result.secret_key,
    publicKey: result.public_key,
  };
}

export function sign(
  secretKey: string,
  action: SignetAction,
  signerName: string,
  signerOwner: string,
): SignetReceipt {
  const actionJson = JSON.stringify(action);
  const receiptJson = wasm_sign(secretKey, actionJson, signerName, signerOwner);
  return JSON.parse(receiptJson);
}

export function verify(receipt: SignetReceipt, publicKey: string): boolean {
  const bare = normalizePublicKey(publicKey);
  return wasm_verify(JSON.stringify(receipt), bare);
}

/**
 * Final outcome attached to a v2/v3 receipt response. Inside the
 * signature scope — tampering invalidates the receipt.
 *
 * Status values:
 * - `verified`: signature/policy verified; not yet executed (rare)
 * - `rejected`: pre-execution check rejected the action
 * - `executed`: action ran and produced a response
 * - `failed`: execution started but failed
 */
export interface SignetOutcome {
  status: 'verified' | 'rejected' | 'executed' | 'failed';
  reason?: string;
  error?: string;
}

export interface SignetResponse {
  content_hash: string;
  /** Optional final outcome. Present when produced by sign_bilateral_with_outcome. */
  outcome?: SignetOutcome;
}

export interface CompoundReceipt {
  v: number;
  id: string;
  action: SignetAction;
  response: SignetResponse;
  signer: SignetSigner;
  ts_request: string;
  ts_response: string;
  nonce: string;
  sig: string;
}

export function signCompound(
  secretKey: string,
  action: SignetAction,
  responseContent: unknown,
  signerName: string,
  signerOwner: string,
  tsRequest: string,
  tsResponse: string,
): CompoundReceipt {
  const json = wasm_sign_compound(
    secretKey,
    JSON.stringify(action),
    JSON.stringify(responseContent),
    signerName,
    signerOwner,
    tsRequest,
    tsResponse,
  );
  return JSON.parse(json) as CompoundReceipt;
}

export function verifyAny(receiptJson: string, publicKey: string): boolean {
  const bare = normalizePublicKey(publicKey);
  try {
    const ok = wasm_verify_any(receiptJson, bare);
    if (ok) {
      const bilateral = parseBilateralReceipt(receiptJson);
      if (bilateral) {
        enforceDefaultBilateralReplayProtection(bilateral);
      }
    }
    return ok;
  } catch (error) {
    if (parseBilateralReceipt(receiptJson) && hasServerKeyMismatch(error)) {
      return false;
    }
    throw error;
  }
}

export interface ServerInfo { pubkey: string; name: string; }

/**
 * Type for the unsigned `extensions` field on bilateral receipts.
 *
 * **WARNING: This field is NOT inside the Ed25519 signature scope.**
 * Modifying `extensions` after signing does NOT invalidate the receipt's
 * signature. Do NOT store security-relevant metadata here (agent identity,
 * trust scores, authorization claims, policy decisions). Safe uses:
 * debugging metadata, display hints, non-security context.
 *
 * See {@link https://github.com/Prismer-AI/signet/blob/main/docs/SECURITY.md SECURITY.md}
 * "Security implications of `extensions`" for details.
 */
export type UnsignedExtensions = Record<string, unknown>;

export interface BilateralReceipt {
  v: number;
  id: string;
  agent_receipt: SignetReceipt;
  response: SignetResponse;
  server: ServerInfo;
  ts_response: string;
  nonce: string;
  sig: string;
  /**
   * @warning NOT inside the signature scope. Tampering is undetectable.
   * Use only for non-security metadata. See {@link UnsignedExtensions}.
   */
  extensions?: UnsignedExtensions;
}

export type BilateralVerifyOutcome = 'agent_self_consistent' | 'agent_trusted';

const DEFAULT_BILATERAL_NONCE_TTL_MS = 60 * 60 * 1000;
const DEFAULT_BILATERAL_NONCE_MAX_ENTRIES = 10_000;
const seenBilateralNonces = new Map<string, number>();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isBilateralReceiptValue(value: unknown): value is BilateralReceipt {
  return isRecord(value)
    && value.v === 3
    && typeof value.nonce === 'string'
    && isRecord(value.agent_receipt)
    && isRecord(value.server);
}

function parseBilateralReceipt(receiptJson: string): BilateralReceipt | null {
  try {
    const parsed = JSON.parse(receiptJson);
    return isBilateralReceiptValue(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function sweepSeenBilateralNonces(now: number): void {
  const cutoff = now - DEFAULT_BILATERAL_NONCE_TTL_MS;
  for (const [nonce, ts] of seenBilateralNonces.entries()) {
    if (ts <= cutoff) {
      seenBilateralNonces.delete(nonce);
    }
  }
  while (seenBilateralNonces.size > DEFAULT_BILATERAL_NONCE_MAX_ENTRIES) {
    const oldest = seenBilateralNonces.keys().next().value;
    if (oldest === undefined) {
      break;
    }
    seenBilateralNonces.delete(oldest);
  }
}

function enforceDefaultBilateralReplayProtection(receipt: BilateralReceipt): void {
  const now = Date.now();
  sweepSeenBilateralNonces(now);
  if (seenBilateralNonces.has(receipt.nonce)) {
    throw new Error(`invalid receipt: bilateral nonce replay detected: ${receipt.nonce}`);
  }
  seenBilateralNonces.set(receipt.nonce, now);
}

function hasServerKeyMismatch(error: unknown): boolean {
  return String(error).includes('caller-supplied server key does not match receipt.server.pubkey');
}

function trustedAgentMatches(
  receipt: BilateralReceipt,
  trustedAgentPublicKey?: string,
): boolean {
  if (trustedAgentPublicKey === undefined) {
    return true;
  }
  return normalizePublicKey(receipt.agent_receipt.signer.pubkey)
    === normalizePublicKey(trustedAgentPublicKey);
}

function serializeReceiptInput(receipt: unknown): { receiptJson: string; bilateral: BilateralReceipt | null } {
  if (typeof receipt === 'string') {
    return { receiptJson: receipt, bilateral: parseBilateralReceipt(receipt) };
  }
  return {
    receiptJson: JSON.stringify(receipt),
    bilateral: isBilateralReceiptValue(receipt) ? receipt : null,
  };
}

export function signBilateral(
  serverKey: string,
  agentReceiptJson: string,
  responseContent: unknown,
  serverName: string,
  tsResponse: string,
): BilateralReceipt {
  const json = wasm_sign_bilateral(serverKey, agentReceiptJson,
    JSON.stringify(responseContent), serverName, tsResponse);
  return JSON.parse(json) as BilateralReceipt;
}

/**
 * Same as `signBilateral` but records a final outcome inside the
 * signature scope. Use when the execution boundary knows whether the
 * action `executed`, `failed`, was `rejected` (e.g. by policy) or only
 * `verified` (signature/policy ok, not yet executed).
 */
export function signBilateralWithOutcome(
  serverKey: string,
  agentReceiptJson: string,
  responseContent: unknown,
  serverName: string,
  tsResponse: string,
  outcome: SignetOutcome | null,
): BilateralReceipt {
  const outcomeJson = outcome === null ? '' : JSON.stringify(outcome);
  const json = wasm_sign_bilateral_with_outcome(
    serverKey, agentReceiptJson,
    JSON.stringify(responseContent), serverName, tsResponse, outcomeJson,
  );
  return JSON.parse(json) as BilateralReceipt;
}

export function verifyBilateral(receiptJson: string, serverPublicKey: string): boolean {
  const bare = normalizePublicKey(serverPublicKey);
  const ok = wasm_verify_bilateral(receiptJson, bare);
  if (ok) {
    const bilateral = parseBilateralReceipt(receiptJson);
    if (bilateral) {
      enforceDefaultBilateralReplayProtection(bilateral);
    }
  }
  return ok;
}

export function contentHash(value: unknown): string {
  return wasm_content_hash(JSON.stringify(value));
}

// ─── Delegation ─────────────────────────────────────────────────────────────

export interface DelegationIdentity {
  pubkey: string;
  name: string;
}

export interface Scope {
  tools: string[];
  targets: string[];
  max_depth: number;
  expires?: string;
  budget?: unknown;
}

export interface DelegationToken {
  v: number;
  id: string;
  delegator: DelegationIdentity;
  delegate: DelegationIdentity;
  scope: Scope;
  issued_at: string;
  nonce: string;
  sig: string;
  correlation_id?: string;
}

export interface Authorization {
  chain: DelegationToken[];
  chain_hash: string;
  root_pubkey: string;
}

export interface AuthorizedReceipt extends SignetReceipt {
  authorization: Authorization;
}

export function signDelegation(
  delegatorKey: string,
  delegatorName: string,
  delegatePubkey: string,
  delegateName: string,
  scope: Scope,
  parentScope?: Scope,
): DelegationToken {
  const bare = delegatePubkey.startsWith('ed25519:')
    ? delegatePubkey.slice('ed25519:'.length)
    : delegatePubkey;
  const json = wasm_sign_delegation(
    delegatorKey,
    delegatorName,
    bare,
    delegateName,
    JSON.stringify(scope),
    parentScope ? JSON.stringify(parentScope) : undefined,
  );
  return JSON.parse(json) as DelegationToken;
}

export function verifyDelegation(token: DelegationToken): boolean {
  return wasm_verify_delegation(JSON.stringify(token));
}

export function signAuthorized(
  key: string,
  action: SignetAction,
  signerName: string,
  chain: DelegationToken[],
): AuthorizedReceipt {
  const json = wasm_sign_authorized(
    key,
    JSON.stringify(action),
    signerName,
    JSON.stringify(chain),
  );
  return JSON.parse(json) as AuthorizedReceipt;
}

export function verifyAuthorized(
  receipt: AuthorizedReceipt,
  trustedRoots: string[],
  clockSkewSecs: number = 60,
): Scope {
  const bareRoots = trustedRoots.map(k =>
    k.startsWith('ed25519:') ? k.slice('ed25519:'.length) : k,
  );
  const json = wasm_verify_authorized(
    JSON.stringify(receipt),
    JSON.stringify(bareRoots),
    BigInt(clockSkewSecs),
  );
  return JSON.parse(json) as Scope;
}

// ─── Policy functions ───────────────────────────────────────────────────────

export interface PolicyEvalResult {
  decision: 'allow' | 'deny' | 'require_approval';
  matched_rules: string[];
  winning_rule: string | null;
  reason: string;
  policy_name: string;
  policy_hash: string;
}

export interface PolicyAttestation {
  policy_hash: string;
  policy_name: string;
  matched_rules: string[];
  decision: 'allow' | 'deny' | 'require_approval';
  reason: string;
}

export interface Policy {
  version: number;
  name: string;
  description?: string;
  default_action?: 'allow' | 'deny' | 'require_approval';
  rules: Array<{
    id: string;
    match: Record<string, unknown>;
    action: 'allow' | 'deny' | 'require_approval';
    reason?: string;
  }>;
}

export interface PolicyReceipt extends SignetReceipt {
  policy: PolicyAttestation;
}

export interface SignWithPolicyResult {
  receipt: PolicyReceipt;
  eval: PolicyEvalResult;
}

export function parsePolicyYaml(yaml: string): Policy {
  const json = wasm_parse_policy_yaml(yaml);
  return JSON.parse(json) as Policy;
}

export function evaluatePolicy(
  action: SignetAction,
  agentName: string,
  policy: Policy,
): PolicyEvalResult {
  const json = wasm_evaluate_policy(
    JSON.stringify(action),
    agentName,
    JSON.stringify(policy),
  );
  return JSON.parse(json) as PolicyEvalResult;
}

export function signWithPolicy(
  secretKey: string,
  action: SignetAction,
  signerName: string,
  signerOwner: string,
  policy: Policy,
): SignWithPolicyResult {
  const json = wasm_sign_with_policy(
    secretKey,
    JSON.stringify(action),
    signerName,
    signerOwner,
    JSON.stringify(policy),
  );
  return JSON.parse(json) as SignWithPolicyResult;
}

export function computePolicyHash(policy: Policy): string {
  return wasm_compute_policy_hash(JSON.stringify(policy));
}

// ─── Bilateral verify options ───────────────────────────────────────────────

export interface BilateralVerifyOptionsTS {
  expectedSession?: string;
  expectedCallId?: string;
  maxTimeWindowSecs?: number;
  trustedAgentPublicKey?: string;
  disableReplayCheck?: boolean;
}

function verifyBilateralWithOptionsInternal(
  receipt: unknown,
  serverPublicKey: string,
  options: BilateralVerifyOptionsTS,
): BilateralVerifyOutcome | false {
  const { receiptJson, bilateral } = serializeReceiptInput(receipt);
  const bareKey = normalizePublicKey(serverPublicKey);
  const normalizedTrustedAgentPublicKey = options.trustedAgentPublicKey === undefined
    ? undefined
    : parseAndNormalizePublicKey(options.trustedAgentPublicKey, 'trusted agent public key');
  const ok = wasm_verify_bilateral_with_options(
    receiptJson,
    bareKey,
    options.expectedSession ?? '',
    options.expectedCallId ?? '',
    BigInt(options.maxTimeWindowSecs ?? 300),
  );
  if (!ok) {
    return false;
  }
  if (bilateral === null) {
    throw new Error('invalid bilateral receipt: expected v3 receipt payload');
  }
  if (!trustedAgentMatches(bilateral, normalizedTrustedAgentPublicKey)) {
    return false;
  }
  if (!options.disableReplayCheck) {
    enforceDefaultBilateralReplayProtection(bilateral);
  }
  return options.trustedAgentPublicKey === undefined
    ? 'agent_self_consistent'
    : 'agent_trusted';
}

export function verifyBilateralWithOptions(
  receipt: unknown,
  serverPublicKey: string,
  options: BilateralVerifyOptionsTS = {},
): boolean {
  return verifyBilateralWithOptionsInternal(receipt, serverPublicKey, options) !== false;
}

export function verifyBilateralWithOptionsDetailed(
  receipt: unknown,
  serverPublicKey: string,
  options: BilateralVerifyOptionsTS = {},
): BilateralVerifyOutcome {
  const outcome = verifyBilateralWithOptionsInternal(receipt, serverPublicKey, options);
  if (outcome === false) {
    throw new Error('bilateral verification failed');
  }
  return outcome;
}

// ─── Expiration functions ───────────────────────────────────────────────────

export function signWithExpiration(
  secretKey: string,
  action: SignetAction,
  signerName: string,
  signerOwner: string,
  expiresAt: string,
): SignetReceipt {
  const json = wasm_sign_with_expiration(
    secretKey,
    JSON.stringify(action),
    signerName,
    signerOwner,
    expiresAt,
  );
  return JSON.parse(json);
}

export function verifyAllowExpired(receipt: SignetReceipt, publicKey: string): boolean {
  const bareKey = publicKey.startsWith('ed25519:')
    ? publicKey.slice('ed25519:'.length)
    : publicKey;
  return wasm_verify_allow_expired(JSON.stringify(receipt), bareKey);
}
