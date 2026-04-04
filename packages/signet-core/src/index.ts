// @signet-auth/core — TypeScript wrapper for signet WASM
import { wasm_generate_keypair, wasm_sign, wasm_verify, wasm_sign_compound, wasm_verify_any, wasm_sign_bilateral, wasm_verify_bilateral, wasm_content_hash } from '../wasm/signet_wasm.js';

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
  return wasm_verify(JSON.stringify(receipt), publicKey);
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
  return wasm_verify_any(receiptJson, publicKey);
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
  return wasm_verify_bilateral(receiptJson, serverPublicKey);
}

export function contentHash(value: unknown): string {
  return wasm_content_hash(JSON.stringify(value));
}
