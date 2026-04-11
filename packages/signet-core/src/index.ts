// @signet-auth/core — TypeScript wrapper for signet WASM
import { wasm_generate_keypair, wasm_sign, wasm_verify, wasm_sign_compound, wasm_verify_any, wasm_sign_bilateral, wasm_verify_bilateral, wasm_content_hash, wasm_sign_delegation, wasm_verify_delegation, wasm_sign_authorized, wasm_verify_authorized, wasm_parse_policy_yaml, wasm_evaluate_policy, wasm_sign_with_policy, wasm_compute_policy_hash } from '../wasm/signet_wasm.js';

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
  nonce: string;
  sig: string;
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
  const bare = publicKey.startsWith('ed25519:') ? publicKey.slice('ed25519:'.length) : publicKey;
  return wasm_verify(JSON.stringify(receipt), bare);
}

export interface SignetResponse {
  content_hash: string;
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
  const bare = publicKey.startsWith('ed25519:') ? publicKey.slice('ed25519:'.length) : publicKey;
  return wasm_verify_any(receiptJson, bare);
}

export interface ServerInfo { pubkey: string; name: string; }

export interface BilateralReceipt {
  v: number;
  id: string;
  agent_receipt: SignetReceipt;
  response: SignetResponse;
  server: ServerInfo;
  ts_response: string;
  nonce: string;
  sig: string;
  extensions?: unknown;
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

export function verifyBilateral(receiptJson: string, serverPublicKey: string): boolean {
  const bare = serverPublicKey.startsWith('ed25519:')
    ? serverPublicKey.slice('ed25519:'.length)
    : serverPublicKey;
  return wasm_verify_bilateral(receiptJson, bare);
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

export function parsePolicyYaml(yaml: string): unknown {
  const json = wasm_parse_policy_yaml(yaml);
  return JSON.parse(json);
}

export function evaluatePolicy(
  action: SignetAction,
  agentName: string,
  policy: unknown,
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
  policy: unknown,
): SignetReceipt & { policy: PolicyAttestation } {
  const json = wasm_sign_with_policy(
    secretKey,
    JSON.stringify(action),
    signerName,
    signerOwner,
    JSON.stringify(policy),
  );
  return JSON.parse(json);
}

export function computePolicyHash(policy: unknown): string {
  return wasm_compute_policy_hash(JSON.stringify(policy));
}
